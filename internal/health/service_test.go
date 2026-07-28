package health

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"opswarden/internal/backup"
	"opswarden/internal/platform"
	"opswarden/internal/storage"
)

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

func TestDetailedReportsDatabaseAndDisk(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "opswarden.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service, err := NewService(db, t.TempDir(), "test", fixedClock{now: time.Now().UTC()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := service.Detailed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if detail.Database != "ok" || detail.DatabaseDiskFreeBytes == 0 ||
		detail.BackupDiskFreeBytes == 0 {
		t.Fatalf("detail=%+v", detail)
	}
}

var _ platform.Clock = fixedClock{}

func TestMaintenanceStatusOmitsUnknownTimestamps(t *testing.T) {
	encoded, err := json.Marshal(MaintenanceStatus{
		ErrorCodes: []string{}, AuditRetention: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"running":false,"errorCodes":[],"auditRetentionEnabled":true}` {
		t.Fatalf("encoded=%s", encoded)
	}
}

func TestNewServiceRequiresWriter(t *testing.T) {
	_, err := NewService(
		&storage.DB{Reader: &sql.DB{}}, t.TempDir(), "test",
		fixedClock{now: time.Now().UTC()}, nil,
	)
	if err == nil {
		t.Fatal("nil writer accepted")
	}
}

func TestDetailedDegradesAndClassifiesReadOnlyWriter(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "opswarden.db"))
	if err != nil {
		t.Fatal(err)
	}
	originalWriter := db.Writer
	t.Cleanup(func() {
		_ = db.Reader.Close()
		_ = db.Writer.Close()
		_ = originalWriter.Close()
	})
	readOnly, err := sql.Open(
		"sqlite", "file:"+db.Path+"?mode=ro&_pragma=query_only(1)",
	)
	if err != nil {
		t.Fatal(err)
	}
	db.Writer = readOnly
	service, err := NewService(
		db, t.TempDir(), "test", fixedClock{now: time.Now().UTC()}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := service.Detailed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if detail.Status != "degraded" || detail.Database != "readonly" {
		t.Fatalf("detail=%+v", detail)
	}
}

func TestDetailedClassifiesBusyAndUnavailableWriters(t *testing.T) {
	t.Run("busy", func(t *testing.T) {
		db, err := storage.Open(filepath.Join(t.TempDir(), "opswarden.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		lock, err := db.Writer.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lock.Rollback() })
		if _, err := lock.Exec(
			`UPDATE health_probe SET marker = marker + 1 WHERE id = 1`,
		); err != nil {
			t.Fatal(err)
		}
		probeWriter, err := sql.Open(
			"sqlite", "file:"+db.Path+"?_pragma=busy_timeout(1)",
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = probeWriter.Close() })
		service, err := NewService(
			&storage.DB{
				Reader: db.Reader, Writer: probeWriter, Path: db.Path,
			},
			t.TempDir(), "test", fixedClock{now: time.Now().UTC()}, nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		detail, err := service.Detailed(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if detail.Status != "degraded" || detail.Database != "busy" {
			t.Fatalf("detail=%+v", detail)
		}
	})

	t.Run("unavailable", func(t *testing.T) {
		db, err := storage.Open(filepath.Join(t.TempDir(), "opswarden.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		closedWriter, err := sql.Open("sqlite", "file:"+db.Path)
		if err != nil {
			t.Fatal(err)
		}
		if err := closedWriter.Close(); err != nil {
			t.Fatal(err)
		}
		service, err := NewService(
			&storage.DB{
				Reader: db.Reader, Writer: closedWriter, Path: db.Path,
			},
			t.TempDir(), "test", fixedClock{now: time.Now().UTC()}, nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		detail, err := service.Detailed(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if detail.Status != "degraded" || detail.Database != "unavailable" {
			t.Fatalf("detail=%+v", detail)
		}
	})
}

func TestDetailedBoundsSingleConnectionWriterProbeAndRecovers(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "opswarden.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	lock, err := db.Writer.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(
		db, t.TempDir(), "test", fixedClock{now: time.Now().UTC()}, nil,
	)
	if err != nil {
		_ = lock.Rollback()
		t.Fatal(err)
	}
	type result struct {
		detail Detail
		err    error
	}
	results := make(chan result, 1)
	started := time.Now()
	go func() {
		detail, err := service.Detailed(context.Background())
		results <- result{detail: detail, err: err}
	}()
	select {
	case got := <-results:
		if got.err != nil {
			_ = lock.Rollback()
			t.Fatal(got.err)
		}
		if got.detail.Status != "degraded" || got.detail.Database != "busy" {
			_ = lock.Rollback()
			t.Fatalf("detail=%+v", got.detail)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			_ = lock.Rollback()
			t.Fatalf("writer probe elapsed=%v", elapsed)
		}
	case <-time.After(2 * time.Second):
		_ = lock.Rollback()
		<-results
		t.Fatal("writer probe blocked on the single-connection pool")
	}
	if err := lock.Rollback(); err != nil {
		t.Fatal(err)
	}
	recovered, err := service.Detailed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Status != "ok" || recovered.Database != "ok" {
		t.Fatalf("recovered detail=%+v", recovered)
	}
}

func TestDetailedPreservesParentDeadlineBeforeBackupVerification(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "opswarden.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	lock, err := db.Writer.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Rollback() })
	backups := &countingBackups{}
	service, err := NewService(
		db, t.TempDir(), "test", fixedClock{now: time.Now().UTC()}, backups,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(
		context.Background(), writerProbeTimeout/4,
	)
	defer cancel()
	started := time.Now()
	if _, err := service.Detailed(ctx); !errors.Is(
		err, context.DeadlineExceeded,
	) {
		t.Fatalf("detail err=%v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("parent deadline elapsed=%v", elapsed)
	}
	if backups.calls != 0 {
		t.Fatalf("backup verification calls=%d", backups.calls)
	}
}

func TestDetailedWriterProbeRollsBackWithoutPersistentChurn(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "opswarden.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Writer.Exec(`
		CREATE TABLE health_probe_writes (count INTEGER NOT NULL);
		INSERT INTO health_probe_writes VALUES (0);
		CREATE TRIGGER count_health_probe_writes
		AFTER UPDATE ON health_probe
		BEGIN
			UPDATE health_probe_writes SET count = count + 1;
		END;
	`); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(
		db, t.TempDir(), "test", fixedClock{now: time.Now().UTC()}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Detailed(context.Background()); err != nil {
		t.Fatal(err)
	}
	var writes int
	if err := db.Reader.QueryRow(
		`SELECT count FROM health_probe_writes`,
	).Scan(&writes); err != nil {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatalf("writer probe persisted %d trigger writes", writes)
	}
}

func TestDetailedDegradesForFailedBackupVerificationAndMaintenance(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "opswarden.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service, err := NewService(
		db, t.TempDir(), "test", fixedClock{now: time.Now().UTC()},
		fakeBackups{record: &backup.RunRecord{
			ID:                    "bkp_0123456789abcdef0123456789abcdef",
			Status:                "succeeded",
			SizeBytes:             4096,
			CompletedAt:           time.Now().UTC(),
			Retained:              true,
			VerificationStatus:    "failed",
			VerificationErrorCode: "BACKUP_CORRUPT",
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	service.SetMaintenance(fakeMaintenance{
		status: MaintenanceStatus{ErrorCodes: []string{"PURGE_FAILED"}},
	})
	detail, err := service.Detailed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if detail.Status != "degraded" || detail.LastBackup == nil ||
		detail.LastBackup.VerificationStatus != "failed" ||
		detail.LastBackup.VerificationErrorCode != "BACKUP_CORRUPT" {
		t.Fatalf("detail=%+v", detail)
	}
}

func TestDetailedDegradesWhenNoCurrentRetainedBackupExists(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "opswarden.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service, err := NewService(
		db, t.TempDir(), "test", fixedClock{now: time.Now().UTC()},
		fakeBackups{},
	)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := service.Detailed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if detail.Status != "degraded" || detail.LastBackup != nil {
		t.Fatalf("detail=%+v", detail)
	}
}

type fakeBackups struct {
	record *backup.RunRecord
	err    error
}

func (provider fakeBackups) LatestSuccessful(context.Context) (*backup.RunRecord, error) {
	return provider.record, provider.err
}

type countingBackups struct{ calls int }

func (provider *countingBackups) LatestSuccessful(
	context.Context,
) (*backup.RunRecord, error) {
	provider.calls++
	return nil, nil
}

type fakeMaintenance struct{ status MaintenanceStatus }

func (provider fakeMaintenance) Status() MaintenanceStatus { return provider.status }
