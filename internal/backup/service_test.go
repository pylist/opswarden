package backup

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"opswarden/internal/platform"
	"opswarden/internal/storage"
)

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

func TestRunCreatesVerifiedOnlineSnapshot(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	dir := filepath.Join(t.TempDir(), "backups")
	service, err := NewService(db, dir, fixedClock{now: time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	path, err := service.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(context.Background(), path, ""); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("unsafe backup mode=%v", info.Mode())
	}
	runs, err := service.ListRuns(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Status != "succeeded" ||
		runs[0].Checksum == "" || runs[0].SizeBytes != info.Size() ||
		strings.Contains(runs[0].Filename, string(filepath.Separator)) {
		t.Fatalf("runs=%+v", runs)
	}
}

var _ platform.Clock = fixedClock{}

func TestVerifyRejectsCorruptionWrongChecksumTraversalAndSymlink(t *testing.T) {
	service, path := runTestBackup(t)
	verification, err := service.Verify(context.Background(), path, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(
		context.Background(), path, strings.Repeat("0", 64),
	); !errors.Is(err, ErrInvalidBackup) {
		t.Fatalf("wrong checksum err=%v", err)
	}
	if _, err := service.Verify(
		context.Background(), filepath.Join(filepath.Dir(path), "..", filepath.Base(path)), "",
	); !errors.Is(err, ErrInvalidBackup) {
		t.Fatalf("traversal err=%v", err)
	}
	link := filepath.Join(
		filepath.Dir(path),
		canonicalFilename(time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC),
			"bkp_11111111111111111111111111111111"),
	)
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(context.Background(), link, verification.Checksum); !errors.Is(err, ErrInvalidBackup) {
		t.Fatalf("symlink err=%v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(context.Background(), path, verification.Checksum); !errors.Is(err, ErrInvalidBackup) {
		t.Fatalf("corrupt err=%v", err)
	}
}

func TestOnlineBackupIsTransactionallyConsistentUnderWALWrites(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Writer.Exec(`
		CREATE TABLE snapshot_probe (id INTEGER PRIMARY KEY, left_value INTEGER, right_value INTEGER);
		INSERT INTO snapshot_probe VALUES (1, 0, 0);
	`); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(
		db, filepath.Join(t.TempDir(), "backups"),
		fixedClock{now: time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for value := 1; value <= 150; value++ {
			if ctx.Err() != nil {
				return
			}
			_, _ = db.Writer.ExecContext(ctx, `
				UPDATE snapshot_probe SET left_value = ?, right_value = ? WHERE id = 1
			`, value, value)
		}
	}()
	path, err := service.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	writer.Wait()
	snapshot, err := sql.Open(
		"sqlite", "file:"+path+"?mode=ro&immutable=1",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	var left, right int
	if err := snapshot.QueryRow(
		`SELECT left_value, right_value FROM snapshot_probe WHERE id = 1`,
	).Scan(&left, &right); err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("torn snapshot: left=%d right=%d", left, right)
	}
}

func TestRetentionSelectionUsesExactUTCWindows(t *testing.T) {
	var records []RunRecord
	base := time.Date(2026, 7, 29, 23, 30, 0, 0, time.UTC)
	for day := 0; day < 220; day++ {
		completed := base.AddDate(0, 0, -day)
		records = append(records, RunRecord{
			ID:          fmt.Sprintf("bkp_%032x", day),
			CompletedAt: completed,
		})
	}
	kept := retentionSet(records)
	expected := make(map[string]struct{})
	addExpectedBuckets(records, 7, func(value time.Time) string {
		return value.UTC().Format("2006-01-02")
	}, expected)
	addExpectedBuckets(records, 4, func(value time.Time) string {
		year, week := value.UTC().ISOWeek()
		return fmt.Sprintf("%04d-W%02d", year, week)
	}, expected)
	addExpectedBuckets(records, 6, func(value time.Time) string {
		return value.UTC().Format("2006-01")
	}, expected)
	if !reflect.DeepEqual(kept, expected) {
		t.Fatalf("kept=%v expected=%v", kept, expected)
	}
}

func TestRetentionTieBreakIsStableAndApplyNeverDeletesUnknownFiles(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clock := &fixedClock{
		now: time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
	}
	dir := filepath.Join(t.TempDir(), "backups")
	service, err := NewService(db, dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	for day := 0; day < 9; day++ {
		clock.now = time.Date(2026, 7, 29-day, 12, 0, 0, 0, time.UTC)
		if _, err := service.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	unknown := filepath.Join(dir, "do-not-delete.txt")
	if err := os.WriteFile(unknown, []byte("operator file"), 0o600); err != nil {
		t.Fatal(err)
	}
	retained, err := service.ApplyRetention(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) >= 9 {
		t.Fatalf("retention did not retire any daily backups: %d", len(retained))
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatalf("unknown file was removed: %v", err)
	}

	tied := []RunRecord{
		{ID: "bkp_" + strings.Repeat("a", 32), CompletedAt: clock.now},
		{ID: "bkp_" + strings.Repeat("b", 32), CompletedAt: clock.now},
	}
	tiedKeep := retentionSet(tied)
	if _, ok := tiedKeep[tied[1].ID]; !ok {
		t.Fatalf("stable lexicographic tie break not applied: %v", tiedKeep)
	}
}

func TestNewServiceRejectsSymlinkBackupDirectory(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "backups")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewService(db, link, fixedClock{now: time.Now().UTC()}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("symlink directory err=%v", err)
	}
}

func addExpectedBuckets(
	records []RunRecord,
	limit int,
	bucket func(time.Time) string,
	expected map[string]struct{},
) {
	seen := make(map[string]struct{})
	for _, record := range records {
		key := bucket(record.CompletedAt)
		if _, ok := seen[key]; ok {
			continue
		}
		if len(seen) == limit {
			break
		}
		seen[key] = struct{}{}
		expected[record.ID] = struct{}{}
	}
}

func TestReconcileClosesPublishedFileRunRecordCrashWindow(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	dir := filepath.Join(t.TempDir(), "backups")
	clock := fixedClock{
		now: time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
	}
	service, err := NewService(db, dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	path, err := service.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	runID := canonicalNamePattern.FindStringSubmatch(filepath.Base(path))[2]
	if _, err := db.Writer.Exec(`
		UPDATE backup_runs
		SET status = 'running', destination = NULL, checksum = NULL,
		    size_bytes = NULL, completed_at = NULL
		WHERE id = ?
	`, runID); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewService(db, dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := recovered.ListRuns(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Status != "succeeded" ||
		runs[0].Filename != filepath.Base(path) || runs[0].Checksum == "" {
		t.Fatalf("recovered runs=%+v", runs)
	}
}

func TestBackupBytesExcludeExternalMasterKeyMaterial(t *testing.T) {
	service, path := runTestBackup(t)
	if _, err := service.Verify(context.Background(), path, ""); err != nil {
		t.Fatal(err)
	}
	masterKey := []byte("unique-raw-master-key-32-bytes!!!")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, masterKey) {
		t.Fatal("external master key material found in backup")
	}
}

func runTestBackup(t *testing.T) (*Service, string) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service, err := NewService(
		db, filepath.Join(t.TempDir(), "backups"),
		fixedClock{now: time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)},
	)
	if err != nil {
		t.Fatal(err)
	}
	path, err := service.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return service, path
}
