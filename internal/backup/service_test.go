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
	dir := backupDir(t)
	service, err := NewService(db, dir, fixedClock{now: time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	path, err := service.Run(context.Background())
	if err != nil {
		var code string
		_ = db.Reader.QueryRow(`SELECT COALESCE(error_code, '') FROM backup_runs ORDER BY started_at DESC LIMIT 1`).Scan(&code)
		t.Fatalf("%v code=%s", err, code)
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
		db, backupDir(t),
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
	dir := backupDir(t)
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
	var retired int
	if err := db.Reader.QueryRow(`
		SELECT count(*) FROM backup_runs
		WHERE retained = 0 AND verification_status = 'retired'
		  AND verified_at IS NOT NULL AND verification_error_code IS NULL
	`).Scan(&retired); err != nil {
		t.Fatal(err)
	}
	if retired != 9-len(retained) {
		t.Fatalf("retired metadata=%d want=%d", retired, 9-len(retained))
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

func TestNewServiceRejectsRootSharedDirectoryAndDatabaseDirectoryWithoutChmod(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "data", "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewService(db, shared, fixedClock{now: time.Now().UTC()}); err == nil {
		t.Fatal("shared directory accepted")
	}
	info, _ := os.Stat(shared)
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("shared directory was chmodded: %o", info.Mode().Perm())
	}
	if _, err := NewService(db, string(filepath.Separator), fixedClock{now: time.Now().UTC()}); err == nil {
		t.Fatal("filesystem root accepted")
	}
	if _, err := NewService(db, filepath.Dir(db.Path), fixedClock{now: time.Now().UTC()}); err == nil {
		t.Fatal("database directory accepted")
	}
}

func TestNewServiceRejectsDirectorySwapBetweenStatAndOpenRoot(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "data", "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	dir := backupDir(t)
	original := dir + "-original"
	attacker := dir + "-attacker"
	const sentinel = "attacker-owned-content"

	originalOpenRoot := openBackupRoot
	t.Cleanup(func() { openBackupRoot = originalOpenRoot })
	openBackupRoot = func(path string) (*os.Root, error) {
		if err := os.Rename(path, original); err != nil {
			return nil, err
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(
			filepath.Join(path, "sentinel"), []byte(sentinel), 0o600,
		); err != nil {
			return nil, err
		}
		root, err := os.OpenRoot(path)
		if err != nil {
			return nil, err
		}
		if err := os.Rename(path, attacker); err != nil {
			_ = root.Close()
			return nil, err
		}
		if err := os.Rename(original, path); err != nil {
			_ = root.Close()
			return nil, err
		}
		return root, nil
	}

	if _, err := NewService(
		db, dir, fixedClock{now: time.Now().UTC()},
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("directory swap err=%v", err)
	}
	content, err := os.ReadFile(filepath.Join(attacker, "sentinel"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != sentinel {
		t.Fatalf("attacker file changed: %q", content)
	}
	entries, err := os.ReadDir(attacker)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "sentinel" {
		t.Fatalf("attacker directory changed: %v", entries)
	}
}

func TestServiceRejectsReplacedOrPermissionChangedBackupDirectory(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "data", "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	dir := backupDir(t)
	service, err := NewService(db, dir, fixedClock{now: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Run(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("permission change err=%v", err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("directory mode changed: info=%v err=%v", info, err)
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	moved := dir + "-moved"
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Run(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("directory replacement err=%v", err)
	}
}

func TestRunNeverWritesThroughReplacedBackupDirectoryPath(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "data", "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	dir := backupDir(t)
	service, err := NewService(db, dir, fixedClock{now: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	moved := dir + "-moved"
	service.beforeOnlineCopy = func() {
		if err := os.Rename(dir, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := service.Run(context.Background()); err == nil {
		t.Fatal("run succeeded after directory replacement")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("replacement directory received files: %v", entries)
	}
}

func TestOnlineCopyUsesReservedRootBoundFile(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service, err := NewService(
		db, backupDir(t), fixedClock{now: time.Now().UTC()},
	)
	if err != nil {
		t.Fatal(err)
	}
	const name = "descriptor-probe.partial"
	if err := service.reserveTemp(name); err != nil {
		t.Fatal(err)
	}
	if err := service.onlineCopy(context.Background(), name); err != nil {
		t.Fatalf("online copy: %T %v", err, err)
	}
	if _, err := service.verifyRelative(
		context.Background(), name, "",
	); err != nil {
		t.Fatalf("root-bound integrity: %T %v", err, err)
	}
}

func TestBackupFileOperationsRejectInjectedForeignOwner(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service, err := NewService(
		db, backupDir(t), fixedClock{now: time.Now().UTC()},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	const name = "foreign-owner.partial"
	if err := service.reserveTemp(name); err != nil {
		t.Fatal(err)
	}
	originalOwnerCheck := backupFileOwnedByCurrentUser
	backupFileOwnedByCurrentUser = func(os.FileInfo) bool { return false }
	t.Cleanup(func() {
		backupFileOwnedByCurrentUser = originalOwnerCheck
		_ = service.root.Remove(name)
	})

	if err := service.onlineCopy(context.Background(), name); err == nil {
		t.Fatal("online copy accepted foreign-owned file")
	}
	info, err := service.root.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("foreign-owned file received %d bytes", info.Size())
	}
	if err := service.chmodFile(name, 0o600); err == nil {
		t.Fatal("chmod accepted foreign-owned file")
	}
	if err := service.syncFile(name); err == nil {
		t.Fatal("sync accepted foreign-owned file")
	}
	if err := service.publishLink(name, "foreign-owner-linked.partial"); err == nil {
		t.Fatal("link accepted foreign-owned file")
	}
	if _, err := service.verifyRelative(
		context.Background(), name, "",
	); !errors.Is(err, ErrInvalidBackup) {
		t.Fatalf("verify foreign-owned file err=%v", err)
	}
	if err := service.removeOwnedBackupFile(name, 1); err == nil {
		t.Fatal("remove accepted foreign-owned file")
	}
	if _, err := service.root.Lstat(name); err != nil {
		t.Fatalf("foreign-owned file was removed: %v", err)
	}
}

func TestSnapshotSizeLimitIsBoundedBeforeAllocation(t *testing.T) {
	if err := validateSnapshotSize(
		maxSnapshotBytes/4096, 4096,
	); err != nil {
		t.Fatalf("boundary rejected: %v", err)
	}
	if err := validateSnapshotSize(
		maxSnapshotBytes/4096+1, 4096,
	); !errors.Is(err, ErrInvalidBackup) {
		t.Fatalf("oversized snapshot err=%v", err)
	}
	if err := validateSnapshotSize(1<<62, 4096); !errors.Is(err, ErrInvalidBackup) {
		t.Fatalf("overflowing snapshot err=%v", err)
	}
}

func TestNewServiceRejectsSymlinkInBackupDirectoryAncestor(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "data", "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	ancestor := filepath.Join(base, "linked-parent")
	if err := os.Symlink(target, ancestor); err != nil {
		t.Fatal(err)
	}
	if _, err := NewService(
		db, filepath.Join(ancestor, "backups"), fixedClock{now: time.Now().UTC()},
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ancestor symlink err=%v", err)
	}
}

func TestVerifyRejectsMultiplyLinkedBackupFile(t *testing.T) {
	service, path := runTestBackup(t)
	link := filepath.Join(filepath.Dir(path), "operator-hard-link.sqlite3")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(
		context.Background(), path, "",
	); !errors.Is(err, ErrInvalidBackup) {
		t.Fatalf("hard-linked backup err=%v", err)
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
	dir := backupDir(t)
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

func TestReconcilePublishesRunAfterLinkBeforePartialRemovalCrashWindow(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	dir := backupDir(t)
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
	name := filepath.Base(path)
	id := canonicalNamePattern.FindStringSubmatch(name)[2]
	partial := "." + name + ".partial"
	if err := os.Link(path, filepath.Join(dir, partial)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer.Exec(`
		UPDATE backup_runs
		SET status = 'running', destination = NULL, checksum = NULL,
		    size_bytes = NULL, completed_at = NULL,
		    verification_status = 'unknown', verified_at = NULL
		WHERE id = ?
	`, id); err != nil {
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
		runs[0].VerificationStatus != "passed" {
		t.Fatalf("runs=%+v", runs)
	}
	if _, err := recovered.root.Lstat(partial); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial link remains: %v", err)
	}
}

func TestLatestSuccessfulPersistsCurrentFileVerificationState(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clock := &fixedClock{
		now: time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
	}
	service, err := NewService(db, backupDir(t), clock)
	if err != nil {
		t.Fatal(err)
	}
	path, err := service.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	latest, err := service.LatestSuccessful(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || latest.VerificationStatus != "passed" ||
		latest.VerifiedAt.IsZero() || latest.VerificationErrorCode != "" {
		t.Fatalf("verified latest=%+v", latest)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(time.Minute)
	latest, err = service.LatestSuccessful(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || latest.VerificationStatus != "failed" ||
		latest.VerificationErrorCode != "BACKUP_MISSING" ||
		latest.VerifiedAt.IsZero() {
		t.Fatalf("missing latest=%+v", latest)
	}

	clock.now = clock.now.Add(time.Minute)
	newPath, err := service.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	latest, err = service.LatestSuccessful(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || latest.Filename != filepath.Base(newPath) ||
		latest.VerificationStatus != "passed" ||
		latest.VerificationErrorCode != "" {
		t.Fatalf("recovered latest=%+v", latest)
	}
}

func TestLatestSuccessfulPersistsCorruptFileVerificationState(t *testing.T) {
	service, path := runTestBackup(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	latest, err := service.LatestSuccessful(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || latest.VerificationStatus != "failed" ||
		latest.VerificationErrorCode != "BACKUP_CORRUPT" {
		t.Fatalf("latest=%+v", latest)
	}
}

func TestLatestSuccessfulCancellationDoesNotMarkValidBackupCorrupt(t *testing.T) {
	service, _ := runTestBackup(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.LatestSuccessful(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	var status, code string
	if err := service.db.Reader.QueryRow(`
		SELECT verification_status, COALESCE(verification_error_code, '')
		FROM backup_runs
		ORDER BY completed_at DESC LIMIT 1
	`).Scan(&status, &code); err != nil {
		t.Fatal(err)
	}
	if status != "passed" || code != "" {
		t.Fatalf("verification status=%q code=%q", status, code)
	}
}

func TestReconcileRestoresRetiredMetadataWhenCanonicalFileStillExists(t *testing.T) {
	service, path := runTestBackup(t)
	name := filepath.Base(path)
	id := canonicalNamePattern.FindStringSubmatch(name)[2]
	if _, err := service.db.Writer.Exec(`
		UPDATE backup_runs
		SET retained = 0, deleted_at = ?,
		    verification_status = 'retired', verified_at = ?
		WHERE id = ?
	`, formatTime(time.Now().UTC()), formatTime(time.Now().UTC()), id); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewService(service.db, service.dir, service.clock)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := recovered.ListRuns(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || !runs[0].Retained ||
		runs[0].VerificationStatus != "passed" ||
		runs[0].VerificationErrorCode != "" {
		t.Fatalf("runs=%+v", runs)
	}
}

func TestReconcileRetiredRowsIterationFailureDoesNotRecoverMetadata(t *testing.T) {
	service, path := runTestBackup(t)
	name := filepath.Base(path)
	id := canonicalNamePattern.FindStringSubmatch(name)[2]
	if _, err := service.db.Writer.Exec(`
		UPDATE backup_runs
		SET retained = 0, deleted_at = ?,
		    verification_status = 'retired', verified_at = ?
		WHERE id = ?
	`, formatTime(time.Now().UTC()), formatTime(time.Now().UTC()), id); err != nil {
		t.Fatal(err)
	}
	iterationErr := errors.New("retired iteration failed")
	service.reconcileRetiredRowScannedHook = func() error {
		return iterationErr
	}
	if err := service.reconcileRetiredRows(
		context.Background(),
	); !errors.Is(err, iterationErr) {
		t.Fatalf("reconcile err=%v", err)
	}
	var retained int
	var verificationStatus string
	if err := service.db.Reader.QueryRow(`
		SELECT retained, verification_status
		FROM backup_runs WHERE id = ?
	`, id).Scan(&retained, &verificationStatus); err != nil {
		t.Fatal(err)
	}
	if retained != 0 || verificationStatus != "retired" {
		t.Fatalf(
			"retained=%d verification_status=%q",
			retained, verificationStatus,
		)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("retired file changed: %v", err)
	}
}

func TestReconcileClosesPrePublishRunAndRemovesPartialFile(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clock := fixedClock{
		now: time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
	}
	service, err := NewService(db, backupDir(t), clock)
	if err != nil {
		t.Fatal(err)
	}
	id := "bkp_22222222222222222222222222222222"
	if err := service.recordStart(context.Background(), id, clock.now); err != nil {
		t.Fatal(err)
	}
	temp := "." + canonicalFilename(clock.now, id) + ".partial"
	if err := service.reserveTemp(temp); err != nil {
		t.Fatal(err)
	}
	runs, err := service.ListRuns(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Status != "failed" ||
		runs[0].ErrorCode != "INTERRUPTED" ||
		runs[0].VerificationStatus != "failed" {
		t.Fatalf("runs=%+v", runs)
	}
	if _, err := service.root.Lstat(temp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial file remains: %v", err)
	}
}

func TestReconcileRunningRowsIterationFailureDoesNotMutateRunOrPartial(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clock := fixedClock{
		now: time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
	}
	service, err := NewService(db, backupDir(t), clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	const id = "bkp_11111111111111111111111111111111"
	if err := service.recordStart(context.Background(), id, clock.now); err != nil {
		t.Fatal(err)
	}
	name := canonicalFilename(clock.now, id)
	partial := "." + name + ".partial"
	if err := service.reserveTemp(partial); err != nil {
		t.Fatal(err)
	}
	iterationErr := errors.New("running iteration failed")
	service.reconcileRunningRowScannedHook = func() error {
		return iterationErr
	}
	if err := service.reconcileRunningRows(
		context.Background(),
	); !errors.Is(err, iterationErr) {
		t.Fatalf("reconcile err=%v", err)
	}
	var status string
	if err := db.Reader.QueryRow(
		`SELECT status FROM backup_runs WHERE id = ?`, id,
	).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "running" {
		t.Fatalf("status=%q", status)
	}
	if _, err := service.root.Lstat(partial); err != nil {
		t.Fatalf("partial changed: %v", err)
	}
}

func TestReconcileWaitsForActiveRunLockBeforeClosingRunningRow(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clock := fixedClock{
		now: time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
	}
	service, err := NewService(db, backupDir(t), clock)
	if err != nil {
		t.Fatal(err)
	}
	id := "bkp_33333333333333333333333333333333"
	if err := service.recordStart(context.Background(), id, clock.now); err != nil {
		t.Fatal(err)
	}
	service.runMu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := service.ListRuns(context.Background(), 10)
		done <- err
	}()
	select {
	case err := <-done:
		service.runMu.Unlock()
		t.Fatalf("reconcile bypassed active run lock: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	var status string
	if err := db.Reader.QueryRow(
		`SELECT status FROM backup_runs WHERE id = ?`, id,
	).Scan(&status); err != nil {
		service.runMu.Unlock()
		t.Fatal(err)
	}
	if status != "running" {
		service.runMu.Unlock()
		t.Fatalf("active row status=%q", status)
	}
	service.runMu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRestoredSnapshotClosesRunningRowInDifferentBackupDirectory(t *testing.T) {
	service, snapshotPath := runTestBackup(t)
	_ = service
	raw, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	restoredPath := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(restoredPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := storage.Open(restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close() })
	recovered, err := NewService(
		restored, backupDir(t),
		fixedClock{now: time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)},
	)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := recovered.ListRuns(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Status != "failed" ||
		runs[0].ErrorCode != "INTERRUPTED" {
		t.Fatalf("restored runs=%+v", runs)
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
		db, backupDir(t),
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

func backupDir(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(base, "backups")
}
