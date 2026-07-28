package backup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"opswarden/internal/platform"
	"opswarden/internal/storage"

	sqlite "modernc.org/sqlite"
)

const (
	filePrefix = "opswarden-"
	fileSuffix = ".sqlite3"
)

var (
	ErrUnavailable       = errors.New("backup unavailable")
	ErrInvalidBackup     = errors.New("invalid backup")
	ErrBackupInProgress  = errors.New("backup already in progress")
	ErrRetentionPartial  = errors.New("backup retention incomplete")
	canonicalNamePattern = regexp.MustCompile(
		`^opswarden-(\d{8}T\d{6}\.\d{9}Z)-(bkp_[0-9a-f]{32})\.sqlite3$`,
	)
)

type RunRecord struct {
	ID          string    `json:"id"`
	Status      string    `json:"status"`
	Filename    string    `json:"filename,omitempty"`
	Checksum    string    `json:"checksum,omitempty"`
	SizeBytes   int64     `json:"sizeBytes,omitempty"`
	StartedAt   time.Time `json:"startedAt"`
	CompletedAt time.Time `json:"completedAt,omitempty,omitzero"`
	ErrorCode   string    `json:"errorCode,omitempty"`
	Retained    bool      `json:"retained"`
}

type Verification struct {
	Checksum string
	Size     int64
}

type Service struct {
	db    *storage.DB
	dir   string
	clock platform.Clock
	runMu sync.Mutex
}

func NewService(db *storage.DB, directory string, clock platform.Clock) (*Service, error) {
	if db == nil || db.Writer == nil || db.Reader == nil || directory == "" ||
		clock == nil {
		return nil, ErrUnavailable
	}
	absolute, err := filepath.Abs(directory)
	if err != nil || filepath.Clean(absolute) != absolute {
		return nil, ErrUnavailable
	}
	if err := ensurePrivateDirectory(absolute); err != nil {
		return nil, ErrUnavailable
	}
	service := &Service{db: db, dir: absolute, clock: clock}
	if err := service.reconcile(context.Background()); err != nil {
		return nil, ErrUnavailable
	}
	return service, nil
}

func (s *Service) Directory() string {
	if s == nil {
		return ""
	}
	return s.dir
}

func (s *Service) Run(ctx context.Context) (path string, resultErr error) {
	if s == nil || ctx == nil {
		return "", ErrUnavailable
	}
	if !s.runMu.TryLock() {
		return "", ErrBackupInProgress
	}
	defer s.runMu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := ensurePrivateDirectory(s.dir); err != nil {
		return "", ErrUnavailable
	}

	now := s.clock.Now().UTC()
	if now.IsZero() {
		return "", ErrUnavailable
	}
	id, err := randomID()
	if err != nil {
		return "", ErrUnavailable
	}
	filename := canonicalFilename(now, id)
	finalPath, ok := s.confinedPath(filename)
	if !ok {
		return "", ErrUnavailable
	}
	tempName := "." + filename + ".partial"
	tempPath, ok := s.confinedPath(tempName)
	if !ok {
		return "", ErrUnavailable
	}
	if err := reserveTemp(tempPath); err != nil {
		return "", ErrUnavailable
	}
	defer func() {
		if resultErr != nil {
			_ = os.Remove(tempPath)
		}
	}()
	if err := s.recordStart(ctx, id, now); err != nil {
		return "", ErrUnavailable
	}
	fail := func(code string) {
		_ = s.recordFailure(context.Background(), id, s.clock.Now().UTC(), code)
	}

	if err := s.onlineCopy(ctx, tempPath); err != nil {
		fail(classifyError(err))
		return "", publicError(err)
	}
	if err := os.Chmod(tempPath, 0o600); err != nil {
		fail("FILESYSTEM_ERROR")
		return "", ErrUnavailable
	}
	verification, err := verifyFile(ctx, tempPath, "")
	if err != nil {
		fail(classifyError(err))
		return "", publicError(err)
	}
	if err := syncFile(tempPath); err != nil {
		fail("FILESYSTEM_ERROR")
		return "", ErrUnavailable
	}
	// Link publishes without replacing an existing name. The random run id makes
	// collisions practically impossible, while link(2) still fails closed.
	if err := os.Link(tempPath, finalPath); err != nil {
		fail("PUBLISH_ERROR")
		return "", ErrUnavailable
	}
	if err := os.Remove(tempPath); err != nil {
		_ = os.Remove(finalPath)
		fail("FILESYSTEM_ERROR")
		return "", ErrUnavailable
	}
	if err := syncDirectory(s.dir); err != nil {
		_ = os.Remove(finalPath)
		fail("FILESYSTEM_ERROR")
		return "", ErrUnavailable
	}
	completed := s.clock.Now().UTC()
	if completed.Before(now) {
		completed = now
	}
	if err := s.recordSuccess(
		ctx, id, filename, verification, completed,
	); err != nil {
		// The fully verified canonical file remains. reconcile will recover this
		// deliberate rename/record crash window idempotently.
		return "", ErrUnavailable
	}
	return finalPath, nil
}

func (s *Service) onlineCopy(ctx context.Context, destination string) error {
	conn, err := s.db.Reader.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	destinationURI := (&url.URL{Scheme: "file", Path: destination}).String()
	return conn.Raw(func(driverConn any) error {
		backuper, ok := driverConn.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("online backup unsupported")
		}
		operation, err := backuper.NewBackup(destinationURI)
		if err != nil {
			return err
		}
		finished := false
		defer func() {
			if !finished {
				_ = operation.Finish()
			}
		}()
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			more, err := operation.Step(256)
			if err != nil {
				return err
			}
			if !more {
				if err := operation.Finish(); err != nil {
					return err
				}
				finished = true
				return nil
			}
		}
	})
}

func (s *Service) Verify(
	ctx context.Context,
	path string,
	expectedChecksum string,
) (Verification, error) {
	if s == nil || ctx == nil {
		return Verification{}, ErrUnavailable
	}
	safePath, ok := s.validateCanonicalPath(path)
	if !ok {
		return Verification{}, ErrInvalidBackup
	}
	return verifyFile(ctx, safePath, expectedChecksum)
}

func (s *Service) ListRuns(
	ctx context.Context,
	limit int,
) ([]RunRecord, error) {
	if s == nil || ctx == nil {
		return nil, ErrUnavailable
	}
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 200 {
		return nil, ErrInvalidBackup
	}
	if err := s.reconcile(ctx); err != nil {
		return nil, ErrUnavailable
	}
	rows, err := s.db.Reader.QueryContext(ctx, `
		SELECT id, status, COALESCE(destination, ''), COALESCE(checksum, ''),
		       COALESCE(size_bytes, 0), started_at, COALESCE(completed_at, ''),
		       COALESCE(error_code, ''), retained
		FROM backup_runs
		ORDER BY started_at DESC, id DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	records := make([]RunRecord, 0, limit)
	for rows.Next() {
		var record RunRecord
		var started, completed string
		var retained int
		if err := rows.Scan(
			&record.ID, &record.Status, &record.Filename, &record.Checksum,
			&record.SizeBytes, &started, &completed, &record.ErrorCode,
			&retained,
		); err != nil {
			return nil, ErrUnavailable
		}
		if !validRunID(record.ID) || !validStatus(record.Status) ||
			(record.Filename != "" && !canonicalFilenameForID(record.Filename, record.ID)) ||
			(record.Checksum != "" && !validChecksum(record.Checksum)) {
			return nil, ErrUnavailable
		}
		record.StartedAt, err = parseTime(started)
		if err != nil {
			return nil, ErrUnavailable
		}
		if completed != "" {
			record.CompletedAt, err = parseTime(completed)
			if err != nil {
				return nil, ErrUnavailable
			}
		}
		record.Retained = retained == 1
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, ErrUnavailable
	}
	return records, nil
}

func (s *Service) LatestSuccessful(ctx context.Context) (*RunRecord, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	var record RunRecord
	var started, completed string
	err := s.db.Reader.QueryRowContext(ctx, `
		SELECT id, status, destination, checksum, size_bytes, started_at,
		       completed_at, retained
		FROM backup_runs
		WHERE status = 'succeeded'
		ORDER BY completed_at DESC, id DESC
		LIMIT 1
	`).Scan(
		&record.ID, &record.Status, &record.Filename, &record.Checksum,
		&record.SizeBytes, &started, &completed, &record.Retained,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil || !canonicalFilenameForID(record.Filename, record.ID) ||
		!validChecksum(record.Checksum) {
		return nil, ErrUnavailable
	}
	record.StartedAt, err = parseTime(started)
	if err != nil {
		return nil, ErrUnavailable
	}
	record.CompletedAt, err = parseTime(completed)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &record, nil
}

// ApplyRetention verifies every candidate before deleting only canonical,
// authoritative backup files outside the approved UTC windows.
func (s *Service) ApplyRetention(ctx context.Context) ([]RunRecord, error) {
	if s == nil || ctx == nil {
		return nil, ErrUnavailable
	}
	if !s.runMu.TryLock() {
		return nil, ErrBackupInProgress
	}
	defer s.runMu.Unlock()
	records, err := s.successfulRetained(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	var retained []RunRecord
	var partial bool
	verified := make([]RunRecord, 0, len(records))
	for _, record := range records {
		path, ok := s.confinedPath(record.Filename)
		if !ok || !canonicalFilenameForID(record.Filename, record.ID) {
			partial = true
			continue
		}
		if _, err := s.Verify(ctx, path, record.Checksum); err != nil {
			partial = true
			retained = append(retained, record)
			continue
		}
		verified = append(verified, record)
	}
	keep := retentionSet(verified)
	for _, record := range verified {
		path, _ := s.confinedPath(record.Filename)
		if _, selected := keep[record.ID]; selected {
			retained = append(retained, record)
			continue
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			partial = true
			retained = append(retained, record)
			continue
		}
		deletedAt := formatTime(s.clock.Now().UTC())
		result, err := s.db.Writer.ExecContext(ctx, `
			UPDATE backup_runs
			SET retained = 0, deleted_at = ?
			WHERE id = ? AND retained = 1 AND status = 'succeeded'
		`, deletedAt, record.ID)
		if err != nil {
			partial = true
			retained = append(retained, record)
			continue
		}
		affected, err := result.RowsAffected()
		if err != nil || affected != 1 {
			partial = true
			retained = append(retained, record)
			continue
		}
		if err := os.Remove(path); err != nil {
			_, _ = s.db.Writer.ExecContext(context.Background(), `
			UPDATE backup_runs
			SET retained = 1, deleted_at = NULL
			WHERE id = ? AND retained = 0 AND status = 'succeeded'
		`, record.ID)
			partial = true
			retained = append(retained, record)
			continue
		}
	}
	if err := syncDirectory(s.dir); err != nil {
		partial = true
	}
	if partial {
		return retained, ErrRetentionPartial
	}
	return retained, nil
}

func retentionSet(records []RunRecord) map[string]struct{} {
	sorted := append([]RunRecord(nil), records...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].CompletedAt.Equal(sorted[j].CompletedAt) {
			return sorted[i].ID > sorted[j].ID
		}
		return sorted[i].CompletedAt.After(sorted[j].CompletedAt)
	})
	keep := make(map[string]struct{})
	selectBuckets(sorted, 7, func(t time.Time) string {
		return t.UTC().Format("2006-01-02")
	}, keep)
	selectBuckets(sorted, 4, func(t time.Time) string {
		year, week := t.UTC().ISOWeek()
		return fmt.Sprintf("%04d-W%02d", year, week)
	}, keep)
	selectBuckets(sorted, 6, func(t time.Time) string {
		return t.UTC().Format("2006-01")
	}, keep)
	return keep
}

func selectBuckets(
	records []RunRecord,
	limit int,
	bucket func(time.Time) string,
	keep map[string]struct{},
) {
	seen := make(map[string]struct{}, limit)
	for _, record := range records {
		key := bucket(record.CompletedAt)
		if _, ok := seen[key]; ok {
			continue
		}
		if len(seen) == limit {
			return
		}
		seen[key] = struct{}{}
		keep[record.ID] = struct{}{}
	}
}

func (s *Service) successfulRetained(ctx context.Context) ([]RunRecord, error) {
	rows, err := s.db.Reader.QueryContext(ctx, `
		SELECT id, destination, checksum, size_bytes, started_at, completed_at
		FROM backup_runs
		WHERE status = 'succeeded' AND retained = 1
		ORDER BY completed_at DESC, id DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []RunRecord
	for rows.Next() {
		var record RunRecord
		var started, completed string
		record.Status, record.Retained = "succeeded", true
		if err := rows.Scan(
			&record.ID, &record.Filename, &record.Checksum, &record.SizeBytes,
			&started, &completed,
		); err != nil {
			return nil, err
		}
		record.StartedAt, err = parseTime(started)
		if err != nil {
			return nil, err
		}
		record.CompletedAt, err = parseTime(completed)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *Service) reconcile(ctx context.Context) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			continue
		}
		matches := canonicalNamePattern.FindStringSubmatch(entry.Name())
		if matches == nil {
			continue
		}
		id := matches[2]
		var status string
		err := s.db.Reader.QueryRowContext(
			ctx, `SELECT status FROM backup_runs WHERE id = ?`, id,
		).Scan(&status)
		if err == nil && status != "running" {
			continue
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		path, ok := s.confinedPath(entry.Name())
		if !ok {
			continue
		}
		verification, err := verifyFile(ctx, path, "")
		if err != nil {
			if status == "running" {
				_ = s.recordFailure(
					ctx, id, s.clock.Now().UTC(), "RECOVERY_VERIFY_FAILED",
				)
			}
			continue
		}
		started, err := time.Parse("20060102T150405.000000000Z", matches[1])
		if err != nil {
			continue
		}
		if status == "running" {
			err = s.recordSuccess(
				ctx, id, entry.Name(), verification, started,
			)
		} else {
			_, err = s.db.Writer.ExecContext(ctx, `
				INSERT OR IGNORE INTO backup_runs (
					id, status, destination, checksum, size_bytes, started_at,
					completed_at, retained
				) VALUES (?, 'succeeded', ?, ?, ?, ?, ?, 1)
			`, id, entry.Name(), verification.Checksum, verification.Size,
				formatTime(started), formatTime(started))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) recordStart(ctx context.Context, id string, started time.Time) error {
	_, err := s.db.Writer.ExecContext(ctx, `
		INSERT INTO backup_runs (id, status, started_at, retained)
		VALUES (?, 'running', ?, 1)
	`, id, formatTime(started))
	return err
}

func (s *Service) recordSuccess(
	ctx context.Context,
	id, filename string,
	verification Verification,
	completed time.Time,
) error {
	result, err := s.db.Writer.ExecContext(ctx, `
		UPDATE backup_runs
		SET status = 'succeeded', destination = ?, checksum = ?,
		    size_bytes = ?, completed_at = ?, error_message = NULL,
		    error_code = NULL, retained = 1
		WHERE id = ? AND status = 'running'
	`, filename, verification.Checksum, verification.Size,
		formatTime(completed), id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return ErrUnavailable
	}
	return nil
}

func (s *Service) recordFailure(
	ctx context.Context,
	id string,
	completed time.Time,
	code string,
) error {
	if !validErrorCode(code) {
		code = "BACKUP_FAILED"
	}
	_, err := s.db.Writer.ExecContext(ctx, `
		UPDATE backup_runs
		SET status = 'failed', completed_at = ?, error_code = ?,
		    error_message = 'backup operation failed', retained = 0
		WHERE id = ? AND status = 'running'
	`, formatTime(completed), code, id)
	return err
}

func verifyFile(
	ctx context.Context,
	path string,
	expectedChecksum string,
) (Verification, error) {
	if err := ctx.Err(); err != nil {
		return Verification{}, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 {
		return Verification{}, ErrInvalidBackup
	}
	file, err := os.Open(path)
	if err != nil {
		return Verification{}, ErrInvalidBackup
	}
	sum := sha256.New()
	size, copyErr := io.Copy(sum, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || size != info.Size() {
		return Verification{}, ErrInvalidBackup
	}
	checksum := hex.EncodeToString(sum.Sum(nil))
	if expectedChecksum != "" &&
		(!validChecksum(expectedChecksum) ||
			!constantStringEqual(checksum, expectedChecksum)) {
		return Verification{}, ErrInvalidBackup
	}
	location := url.URL{Scheme: "file", Path: path}
	query := url.Values{}
	query.Set("mode", "ro")
	query.Set("immutable", "1")
	query.Add("_pragma", "query_only(1)")
	location.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", location.String())
	if err != nil {
		return Verification{}, ErrInvalidBackup
	}
	defer db.Close()
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil ||
		integrity != "ok" {
		return Verification{}, ErrInvalidBackup
	}
	return Verification{Checksum: checksum, Size: size}, nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnavailable
	}
	return os.Chmod(path, 0o700)
}

func reserveTemp(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func syncFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *Service) validateCanonicalPath(path string) (string, bool) {
	if path == "" || !filepath.IsAbs(path) {
		return "", false
	}
	clean := filepath.Clean(path)
	if clean != path {
		return "", false
	}
	name := filepath.Base(clean)
	if canonicalNamePattern.FindStringSubmatch(name) == nil {
		return "", false
	}
	expected, ok := s.confinedPath(name)
	return expected, ok && expected == clean
}

func (s *Service) confinedPath(name string) (string, bool) {
	if name == "" || filepath.Base(name) != name ||
		strings.ContainsAny(name, `/\`) {
		return "", false
	}
	path := filepath.Join(s.dir, name)
	relative, err := filepath.Rel(s.dir, path)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") ||
		filepath.IsAbs(relative) {
		return "", false
	}
	return path, true
}

func canonicalFilename(now time.Time, id string) string {
	return filePrefix + now.UTC().Format("20060102T150405.000000000Z") +
		"-" + id + fileSuffix
}

func canonicalFilenameForID(filename, id string) bool {
	matches := canonicalNamePattern.FindStringSubmatch(filename)
	return matches != nil && matches[2] == id
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "bkp_" + hex.EncodeToString(raw[:]), nil
}

func validRunID(value string) bool {
	return len(value) == 36 && strings.HasPrefix(value, "bkp_") &&
		allLowerHex(value[4:])
}

func validChecksum(value string) bool {
	return len(value) == sha256.Size*2 && allLowerHex(value)
}

func allLowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validStatus(value string) bool {
	return value == "running" || value == "succeeded" || value == "failed"
}

func validErrorCode(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC ||
		formatTime(parsed) != value {
		return time.Time{}, ErrUnavailable
	}
	return parsed, nil
}

func classifyError(err error) string {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "CANCELED"
	case errors.Is(err, ErrInvalidBackup):
		return "VERIFY_FAILED"
	default:
		return "BACKUP_FAILED"
	}
}

func publicError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, ErrInvalidBackup) {
		return ErrInvalidBackup
	}
	return ErrUnavailable
}

func constantStringEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}
