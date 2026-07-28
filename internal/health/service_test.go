package health

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

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
	if detail.Database != "ok" || detail.DiskFreeBytes == 0 {
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
