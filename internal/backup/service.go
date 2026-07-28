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
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	sqlitevfs "modernc.org/sqlite/vfs"

	"opswarden/internal/platform"
	"opswarden/internal/storage"
)

const (
	filePrefix       = "opswarden-"
	fileSuffix       = ".sqlite3"
	maxSnapshotBytes = int64(128 << 20)
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
	ID                    string    `json:"id"`
	Status                string    `json:"status"`
	Filename              string    `json:"filename,omitempty"`
	Checksum              string    `json:"checksum,omitempty"`
	SizeBytes             int64     `json:"sizeBytes,omitempty"`
	StartedAt             time.Time `json:"startedAt"`
	CompletedAt           time.Time `json:"completedAt,omitempty,omitzero"`
	ErrorCode             string    `json:"errorCode,omitempty"`
	Retained              bool      `json:"retained"`
	VerificationStatus    string    `json:"verificationStatus"`
	VerifiedAt            time.Time `json:"verifiedAt,omitempty,omitzero"`
	VerificationErrorCode string    `json:"verificationErrorCode,omitempty"`
}

type Verification struct {
	Checksum string
	Size     int64
}

type Service struct {
	db      *storage.DB
	dir     string
	root    *os.Root
	dirInfo os.FileInfo
	clock   platform.Clock
	runMu   sync.Mutex

	beforeOnlineCopy func()
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
	info, err := ensurePrivateDirectory(absolute, db.Path)
	if err != nil {
		return nil, ErrUnavailable
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, ErrUnavailable
	}
	service := &Service{
		db: db, dir: absolute, root: root, dirInfo: info, clock: clock,
	}
	if err := service.reconcileLocked(context.Background()); err != nil {
		_ = root.Close()
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

func (s *Service) Close() error {
	if s == nil || s.root == nil {
		return nil
	}
	return s.root.Close()
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
	if err := s.validateDirectory(); err != nil {
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
	if _, ok := s.confinedPath(tempName); !ok {
		return "", ErrUnavailable
	}
	if err := s.reserveTemp(tempName); err != nil {
		return "", ErrUnavailable
	}
	defer func() {
		if resultErr != nil {
			_ = s.root.Remove(tempName)
		}
	}()
	if err := s.recordStart(ctx, id, now); err != nil {
		return "", ErrUnavailable
	}
	fail := func(code string) {
		_ = s.recordFailure(context.Background(), id, s.clock.Now().UTC(), code)
	}

	if s.beforeOnlineCopy != nil {
		s.beforeOnlineCopy()
	}
	if err := s.onlineCopy(ctx, tempName); err != nil {
		fail(classifyError(err))
		return "", publicError(err)
	}
	if err := s.chmodFile(tempName, 0o600); err != nil {
		fail("FILESYSTEM_ERROR")
		return "", ErrUnavailable
	}
	verification, err := s.verifyRelative(ctx, tempName, "")
	if err != nil {
		fail(classifyError(err))
		return "", publicError(err)
	}
	if err := s.syncFile(tempName); err != nil {
		fail("FILESYSTEM_ERROR")
		return "", ErrUnavailable
	}
	// Link publishes without replacing an existing name. The random run id makes
	// collisions practically impossible, while link(2) still fails closed.
	if err := s.publishLink(tempName, filename); err != nil {
		fail("PUBLISH_ERROR")
		return "", ErrUnavailable
	}
	if err := s.root.Remove(tempName); err != nil {
		_ = s.root.Remove(filename)
		fail("FILESYSTEM_ERROR")
		return "", ErrUnavailable
	}
	publishedVerification, err := s.verifyRelative(
		ctx, filename, verification.Checksum,
	)
	if err != nil || publishedVerification.Size != verification.Size {
		_ = s.root.Remove(filename)
		if err == nil {
			err = ErrInvalidBackup
		}
		fail(classifyError(err))
		return "", publicError(err)
	}
	if err := s.syncDirectory(); err != nil {
		_ = s.root.Remove(filename)
		fail("FILESYSTEM_ERROR")
		return "", ErrUnavailable
	}
	if err := s.validateDirectory(); err != nil {
		_ = s.root.Remove(filename)
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

func (s *Service) onlineCopy(ctx context.Context, destinationName string) error {
	file, err := s.root.OpenFile(destinationName, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 || linkCount(info) != 1 {
		return ErrUnavailable
	}
	conn, err := s.db.Reader.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var pageCount, pageSize int64
	if err := tx.QueryRowContext(ctx, `PRAGMA page_count`).Scan(
		&pageCount,
	); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `PRAGMA page_size`).Scan(
		&pageSize,
	); err != nil {
		return err
	}
	if err := validateSnapshotSize(pageCount, pageSize); err != nil {
		return err
	}
	var snapshot []byte
	err = conn.Raw(func(driverConn any) error {
		serializer, ok := driverConn.(interface {
			Serialize() ([]byte, error)
		})
		if !ok {
			return errors.New("online serialization unsupported")
		}
		var serializeErr error
		snapshot, serializeErr = serializer.Serialize()
		return serializeErr
	})
	if err != nil {
		return err
	}
	defer clear(snapshot)
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(snapshot) == 0 || int64(len(snapshot)) > maxSnapshotBytes {
		return ErrInvalidBackup
	}
	if len(snapshot) < 100 ||
		string(snapshot[:16]) != "SQLite format 3\x00" {
		return ErrInvalidBackup
	}
	// Serialize preserves the source journal-mode header. A standalone backup
	// has no WAL sidecars, so normalize the serialized image to rollback mode.
	// Bytes 18 and 19 are the SQLite file read/write format versions.
	snapshot[18], snapshot[19] = 1, 1
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	for offset := 0; offset < len(snapshot); {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := min(offset+(1<<20), len(snapshot))
		written, err := file.Write(snapshot[offset:end])
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		offset += written
	}
	return nil
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
	return s.verifyRelative(ctx, filepath.Base(safePath), expectedChecksum)
}

func (s *Service) ListRuns(
	ctx context.Context,
	limit int,
) ([]RunRecord, error) {
	if s == nil || ctx == nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 200 {
		return nil, ErrInvalidBackup
	}
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if err := s.reconcileLocked(ctx); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrUnavailable
	}
	rows, err := s.db.Reader.QueryContext(ctx, `
		SELECT id, status, COALESCE(destination, ''), COALESCE(checksum, ''),
		       COALESCE(size_bytes, 0), started_at, COALESCE(completed_at, ''),
		       COALESCE(error_code, ''), retained, verification_status,
		       COALESCE(verified_at, ''),
		       COALESCE(verification_error_code, '')
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
		var started, completed, verified string
		var retained int
		if err := rows.Scan(
			&record.ID, &record.Status, &record.Filename, &record.Checksum,
			&record.SizeBytes, &started, &completed, &record.ErrorCode,
			&retained, &record.VerificationStatus, &verified,
			&record.VerificationErrorCode,
		); err != nil {
			return nil, ErrUnavailable
		}
		if !validRunID(record.ID) || !validStatus(record.Status) ||
			!validVerificationStatus(record.VerificationStatus) ||
			(record.Filename != "" && !canonicalFilenameForID(record.Filename, record.ID)) ||
			(record.Checksum != "" && !validChecksum(record.Checksum)) ||
			(record.VerificationErrorCode != "" &&
				!validErrorCode(record.VerificationErrorCode)) {
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
		if verified != "" {
			record.VerifiedAt, err = parseTime(verified)
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
	if s == nil || ctx == nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if err := s.reconcileLocked(ctx); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrUnavailable
	}
	var record RunRecord
	var started, completed, verified string
	err := s.db.Reader.QueryRowContext(ctx, `
		SELECT id, status, destination, checksum, size_bytes, started_at,
		       completed_at, retained, verification_status,
		       COALESCE(verified_at, ''),
		       COALESCE(verification_error_code, '')
		FROM backup_runs
		WHERE status = 'succeeded' AND retained = 1
		ORDER BY completed_at DESC, id DESC
		LIMIT 1
	`).Scan(
		&record.ID, &record.Status, &record.Filename, &record.Checksum,
		&record.SizeBytes, &started, &completed, &record.Retained,
		&record.VerificationStatus, &verified,
		&record.VerificationErrorCode,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || !canonicalFilenameForID(record.Filename, record.ID) ||
		!validChecksum(record.Checksum) ||
		!validVerificationStatus(record.VerificationStatus) ||
		(record.VerificationErrorCode != "" &&
			!validErrorCode(record.VerificationErrorCode)) {
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
	if verified != "" {
		record.VerifiedAt, err = parseTime(verified)
		if err != nil {
			return nil, ErrUnavailable
		}
	}
	verifiedAt := s.clock.Now().UTC()
	if verifiedAt.IsZero() {
		return nil, ErrUnavailable
	}
	verification, verifyErr := s.verifyRelative(
		ctx, record.Filename, record.Checksum,
	)
	if verifyErr != nil {
		if errors.Is(verifyErr, context.Canceled) ||
			errors.Is(verifyErr, context.DeadlineExceeded) {
			return nil, verifyErr
		}
		code := s.verificationFailureCode(record.Filename)
		if err := s.persistVerification(ctx, record.ID, "failed", verifiedAt, code); err != nil {
			return nil, ErrUnavailable
		}
		record.VerificationStatus = "failed"
		record.VerifiedAt = verifiedAt
		record.VerificationErrorCode = code
		return &record, nil
	}
	if verification.Size != record.SizeBytes {
		if err := s.persistVerification(
			ctx, record.ID, "failed", verifiedAt, "BACKUP_CORRUPT",
		); err != nil {
			return nil, ErrUnavailable
		}
		record.VerificationStatus = "failed"
		record.VerifiedAt = verifiedAt
		record.VerificationErrorCode = "BACKUP_CORRUPT"
		return &record, nil
	}
	if err := s.persistVerification(ctx, record.ID, "passed", verifiedAt, ""); err != nil {
		return nil, ErrUnavailable
	}
	record.VerificationStatus = "passed"
	record.VerifiedAt = verifiedAt
	record.VerificationErrorCode = ""
	return &record, nil
}

// ApplyRetention verifies every candidate before deleting only canonical,
// authoritative backup files outside the approved UTC windows.
func (s *Service) ApplyRetention(ctx context.Context) ([]RunRecord, error) {
	if s == nil || ctx == nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !s.runMu.TryLock() {
		return nil, ErrBackupInProgress
	}
	defer s.runMu.Unlock()
	if err := s.validateDirectory(); err != nil {
		return nil, ErrUnavailable
	}
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
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				return retained, err
			}
			_ = s.persistVerification(
				ctx, record.ID, "failed", s.clock.Now().UTC(),
				s.verificationFailureCode(record.Filename),
			)
			partial = true
			retained = append(retained, record)
			continue
		}
		if err := s.persistVerification(
			ctx, record.ID, "passed", s.clock.Now().UTC(), "",
		); err != nil {
			partial = true
			retained = append(retained, record)
			continue
		}
		verified = append(verified, record)
	}
	keep := retentionSet(verified)
	for _, record := range verified {
		if _, selected := keep[record.ID]; selected {
			retained = append(retained, record)
			continue
		}
		info, err := s.root.Lstat(record.Filename)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			partial = true
			retained = append(retained, record)
			continue
		}
		deletedAt := formatTime(s.clock.Now().UTC())
		result, err := s.db.Writer.ExecContext(ctx, `
			UPDATE backup_runs
			SET retained = 0, deleted_at = ?, verification_status = 'retired',
			    verified_at = ?, verification_error_code = NULL
			WHERE id = ? AND retained = 1 AND status = 'succeeded'
		`, deletedAt, deletedAt, record.ID)
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
		if err := s.root.Remove(record.Filename); err != nil {
			_, _ = s.db.Writer.ExecContext(context.Background(), `
			UPDATE backup_runs
			SET retained = 1, deleted_at = NULL,
			    verification_status = 'passed', verified_at = ?,
			    verification_error_code = NULL
			WHERE id = ? AND retained = 0 AND status = 'succeeded'
		`, formatTime(s.clock.Now().UTC()), record.ID)
			partial = true
			retained = append(retained, record)
			continue
		}
	}
	if err := s.syncDirectory(); err != nil {
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

func (s *Service) reconcileLocked(ctx context.Context) error {
	if err := s.validateDirectory(); err != nil {
		return err
	}
	if err := s.reconcileRunningRows(ctx); err != nil {
		return err
	}
	if err := s.reconcileRetiredRows(ctx); err != nil {
		return err
	}
	entries, err := fs.ReadDir(s.root.FS(), ".")
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
		_, ok := s.confinedPath(entry.Name())
		if !ok {
			continue
		}
		verification, err := s.verifyRelative(ctx, entry.Name(), "")
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
					completed_at, retained, verification_status, verified_at
				) VALUES (?, 'succeeded', ?, ?, ?, ?, ?, 1, 'passed', ?)
			`, id, entry.Name(), verification.Checksum, verification.Size,
				formatTime(started), formatTime(started), formatTime(started))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) reconcileRetiredRows(ctx context.Context) error {
	rows, err := s.db.Reader.QueryContext(ctx, `
		SELECT id, destination, checksum, size_bytes
		FROM backup_runs
		WHERE status = 'succeeded' AND retained = 0
		  AND verification_status = 'retired'
		ORDER BY id
	`)
	if err != nil {
		return err
	}
	type retired struct {
		id, filename, checksum string
		size                   int64
	}
	var records []retired
	for rows.Next() {
		var record retired
		if err := rows.Scan(
			&record.id, &record.filename, &record.checksum, &record.size,
		); err != nil {
			rows.Close()
			return err
		}
		records = append(records, record)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, record := range records {
		if !validRunID(record.id) ||
			!canonicalFilenameForID(record.filename, record.id) ||
			!validChecksum(record.checksum) || record.size <= 0 {
			return ErrUnavailable
		}
		if _, err := s.root.Lstat(record.filename); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		status, code := "passed", ""
		verification, err := s.verifyRelative(
			ctx, record.filename, record.checksum,
		)
		if err != nil || verification.Size != record.size {
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			status, code = "failed", "BACKUP_CORRUPT"
		}
		verifiedAt := s.clock.Now().UTC()
		if verifiedAt.IsZero() {
			return ErrUnavailable
		}
		result, err := s.db.Writer.ExecContext(ctx, `
			UPDATE backup_runs
			SET retained = 1, deleted_at = NULL,
			    verification_status = ?, verified_at = ?,
			    verification_error_code = NULLIF(?, '')
			WHERE id = ? AND status = 'succeeded' AND retained = 0
			  AND verification_status = 'retired'
		`, status, formatTime(verifiedAt), code, record.id)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil || affected != 1 {
			return ErrUnavailable
		}
	}
	return nil
}

func (s *Service) reconcileRunningRows(ctx context.Context) error {
	rows, err := s.db.Reader.QueryContext(ctx, `
		SELECT id, started_at FROM backup_runs
		WHERE status = 'running'
		ORDER BY started_at, id
	`)
	if err != nil {
		return err
	}
	type running struct{ id, started string }
	var runs []running
	for rows.Next() {
		var run running
		if err := rows.Scan(&run.id, &run.started); err != nil {
			rows.Close()
			return err
		}
		runs = append(runs, run)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, run := range runs {
		started, err := parseTime(run.started)
		if err != nil || !validRunID(run.id) {
			if err := s.recordFailure(
				ctx, run.id, s.clock.Now().UTC(), "INTERRUPTED",
			); err != nil {
				return err
			}
			continue
		}
		name := canonicalFilename(started, run.id)
		temp := "." + name + ".partial"
		if _, err := s.root.Lstat(name); err == nil {
			if _, tempErr := s.root.Lstat(temp); tempErr == nil {
				if err := s.root.Remove(temp); err != nil {
					return err
				}
				if err := s.syncDirectory(); err != nil {
					return err
				}
			} else if !errors.Is(tempErr, os.ErrNotExist) {
				return tempErr
			}
			verification, verifyErr := s.verifyRelative(ctx, name, "")
			if verifyErr != nil {
				if err := s.recordFailure(
					ctx, run.id, s.clock.Now().UTC(), "RECOVERY_VERIFY_FAILED",
				); err != nil {
					return err
				}
				continue
			}
			if err := s.recordSuccess(
				ctx, run.id, name, verification, s.clock.Now().UTC(),
			); err != nil {
				return err
			}
			continue
		}
		if _, err := s.root.Lstat(temp); err == nil {
			if err := s.root.Remove(temp); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := s.recordFailure(
			ctx, run.id, s.clock.Now().UTC(), "INTERRUPTED",
		); err != nil {
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
		    error_code = NULL, retained = 1,
		    verification_status = 'passed', verified_at = ?,
		    verification_error_code = NULL
		WHERE id = ? AND status = 'running'
	`, filename, verification.Checksum, verification.Size,
		formatTime(completed), formatTime(completed), id)
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
		    error_message = 'backup operation failed', retained = 0,
		    verification_status = 'failed', verified_at = ?,
		    verification_error_code = ?
		WHERE id = ? AND status = 'running'
	`, formatTime(completed), code, formatTime(completed), code, id)
	return err
}

func (s *Service) persistVerification(
	ctx context.Context,
	id, status string,
	verifiedAt time.Time,
	errorCode string,
) error {
	if (status != "passed" && status != "failed") ||
		verifiedAt.IsZero() ||
		(errorCode != "" && !validErrorCode(errorCode)) ||
		(status == "passed" && errorCode != "") ||
		(status == "failed" && errorCode == "") {
		return ErrUnavailable
	}
	result, err := s.db.Writer.ExecContext(ctx, `
		UPDATE backup_runs
		SET verification_status = ?, verified_at = ?,
		    verification_error_code = NULLIF(?, '')
		WHERE id = ? AND status = 'succeeded' AND retained = 1
	`, status, formatTime(verifiedAt), errorCode, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return ErrUnavailable
	}
	return nil
}

func (s *Service) verificationFailureCode(filename string) string {
	if _, err := s.root.Lstat(filename); errors.Is(err, os.ErrNotExist) {
		return "BACKUP_MISSING"
	}
	return "BACKUP_CORRUPT"
}

func (s *Service) verifyRelative(
	ctx context.Context,
	name string,
	expectedChecksum string,
) (Verification, error) {
	if err := ctx.Err(); err != nil {
		return Verification{}, err
	}
	if filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
		return Verification{}, ErrInvalidBackup
	}
	if err := s.validateDirectory(); err != nil {
		return Verification{}, ErrInvalidBackup
	}
	info, err := s.root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() <= 0 || linkCount(info) != 1 {
		return Verification{}, ErrInvalidBackup
	}
	file, err := s.root.Open(name)
	if err != nil {
		return Verification{}, ErrInvalidBackup
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() ||
		openedInfo.Mode().Perm() != 0o600 || openedInfo.Size() <= 0 ||
		openedInfo.Size() > maxSnapshotBytes || linkCount(openedInfo) != 1 {
		return Verification{}, ErrInvalidBackup
	}
	if !os.SameFile(info, openedInfo) {
		return Verification{}, ErrInvalidBackup
	}
	digest := sha256.New()
	copied, err := io.Copy(digest, file)
	if err != nil || copied != openedInfo.Size() {
		return Verification{}, ErrInvalidBackup
	}
	checksum := hex.EncodeToString(digest.Sum(nil))
	if expectedChecksum != "" &&
		(!validChecksum(expectedChecksum) ||
			!constantStringEqual(checksum, expectedChecksum)) {
		return Verification{}, ErrInvalidBackup
	}
	if err := verifyOpenedFileIntegrity(
		ctx, s.root, name, openedInfo,
	); err != nil {
		return Verification{}, ErrInvalidBackup
	}
	finalInfo, err := s.root.Lstat(name)
	if err != nil || !finalInfo.Mode().IsRegular() ||
		finalInfo.Mode().Perm() != 0o600 || finalInfo.Size() != openedInfo.Size() ||
		linkCount(finalInfo) != 1 || !os.SameFile(openedInfo, finalInfo) {
		return Verification{}, ErrInvalidBackup
	}
	if err := s.validateDirectory(); err != nil {
		return Verification{}, ErrInvalidBackup
	}
	return Verification{Checksum: checksum, Size: copied}, nil
}

func verifyOpenedFileIntegrity(
	ctx context.Context,
	root *os.Root,
	sourceName string,
	expectedInfo os.FileInfo,
) error {
	const databaseName = "snapshot.sqlite3"
	vfsName, filesystem, err := sqlitevfs.New(singleFileFS{
		root:         root,
		sourceName:   sourceName,
		databaseName: databaseName,
		expectedInfo: expectedInfo,
	})
	if err != nil {
		return err
	}
	defer filesystem.Close()

	location := url.URL{Scheme: "file", Opaque: databaseName}
	query := url.Values{}
	query.Set("immutable", "1")
	query.Set("mode", "ro")
	query.Set("vfs", vfsName)
	location.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", location.String())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var integrity string
	if err := db.QueryRowContext(
		ctx, `PRAGMA integrity_check`,
	).Scan(&integrity); err != nil {
		return err
	}
	if integrity != "ok" {
		return ErrInvalidBackup
	}
	return nil
}

type singleFileFS struct {
	root         *os.Root
	sourceName   string
	databaseName string
	expectedInfo os.FileInfo
}

func (filesystem singleFileFS) Open(name string) (fs.File, error) {
	if filesystem.root == nil || filesystem.expectedInfo == nil ||
		name != filesystem.databaseName {
		return nil, fs.ErrNotExist
	}
	file, err := filesystem.root.Open(filesystem.sourceName)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 ||
		info.Size() != filesystem.expectedInfo.Size() ||
		linkCount(info) != 1 || !os.SameFile(filesystem.expectedInfo, info) {
		_ = file.Close()
		return nil, fs.ErrInvalid
	}
	return file, nil
}

func validateSnapshotSize(pageCount, pageSize int64) error {
	if pageCount <= 0 || pageSize <= 0 ||
		pageCount > maxSnapshotBytes/pageSize {
		return ErrInvalidBackup
	}
	return nil
}

func ensurePrivateDirectory(path, databasePath string) (os.FileInfo, error) {
	volumeRoot := filepath.VolumeName(path) + string(filepath.Separator)
	if path == volumeRoot || (databasePath != "" &&
		path == filepath.Dir(filepath.Clean(databasePath))) {
		return nil, ErrUnavailable
	}
	relative, err := filepath.Rel(volumeRoot, path)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
		return nil, ErrUnavailable
	}
	current := volumeRoot
	parts := strings.Split(relative, string(filepath.Separator))
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, ErrUnavailable
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil {
				return nil, err
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, ErrUnavailable
		}
		if index == len(parts)-1 &&
			(info.Mode().Perm() != 0o700 || !ownedByCurrentUser(info)) {
			return nil, ErrUnavailable
		}
	}
	return os.Lstat(path)
}

func (s *Service) reserveTemp(name string) error {
	file, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		_ = s.root.Remove(name)
		return err
	}
	info, err := s.root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		linkCount(info) != 1 {
		_ = s.root.Remove(name)
		return ErrUnavailable
	}
	return nil
}

func (s *Service) syncFile(name string) error {
	file, err := s.root.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func (s *Service) chmodFile(name string, mode os.FileMode) error {
	file, err := s.root.OpenFile(name, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Chmod(mode)
}

func (s *Service) publishLink(oldName, newName string) error {
	dir, err := s.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return unix.Linkat(
		int(dir.Fd()), oldName, int(dir.Fd()), newName, 0,
	)
}

func (s *Service) validateDirectory() error {
	info, err := os.Lstat(s.dir)
	if err != nil || !os.SameFile(info, s.dirInfo) ||
		!info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 || !ownedByCurrentUser(info) {
		return ErrUnavailable
	}
	return nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

func linkCount(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Nlink)
}

func (s *Service) syncDirectory() error {
	dir, err := s.root.Open(".")
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

func validVerificationStatus(value string) bool {
	return value == "unknown" || value == "passed" ||
		value == "failed" || value == "retired"
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
