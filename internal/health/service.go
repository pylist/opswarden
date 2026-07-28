package health

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"opswarden/internal/backup"
	"opswarden/internal/platform"
	"opswarden/internal/storage"
)

type Liveness struct {
	Status string `json:"status"`
}

type MaintenanceStatus struct {
	Running        bool      `json:"running"`
	LastStartedAt  time.Time `json:"lastStartedAt,omitempty,omitzero"`
	LastFinishedAt time.Time `json:"lastFinishedAt,omitempty,omitzero"`
	LastSuccessAt  time.Time `json:"lastSuccessAt,omitempty,omitzero"`
	NextRunAt      time.Time `json:"nextRunAt,omitempty,omitzero"`
	ErrorCodes     []string  `json:"errorCodes"`
	AuditRetention bool      `json:"auditRetentionEnabled"`
}

type StatusProvider interface {
	Status() MaintenanceStatus
}

type BackupProvider interface {
	LatestSuccessful(context.Context) (*backup.RunRecord, error)
}

type BackupSummary struct {
	ID                    string    `json:"id"`
	Status                string    `json:"status"`
	SizeBytes             int64     `json:"sizeBytes"`
	CompletedAt           time.Time `json:"completedAt"`
	Retained              bool      `json:"retained"`
	VerificationStatus    string    `json:"verificationStatus"`
	VerifiedAt            time.Time `json:"verifiedAt,omitempty,omitzero"`
	VerificationErrorCode string    `json:"verificationErrorCode,omitempty"`
}

type Detail struct {
	Status                string             `json:"status"`
	Version               string             `json:"version"`
	UptimeSeconds         int64              `json:"uptimeSeconds"`
	Database              string             `json:"database"`
	JournalMode           string             `json:"journalMode"`
	DatabaseDiskFreeBytes uint64             `json:"databaseDiskFreeBytes"`
	BackupDiskFreeBytes   uint64             `json:"backupDiskFreeBytes"`
	MigrationVersion      int                `json:"migrationVersion"`
	LastBackup            *BackupSummary     `json:"lastBackup,omitempty"`
	Maintenance           *MaintenanceStatus `json:"maintenance,omitempty"`
}

type Service struct {
	db             *storage.DB
	databasePath   string
	backupDiskPath string
	version        string
	clock          platform.Clock
	startedAt      time.Time
	backups        BackupProvider
	maintenance    StatusProvider
}

func NewService(
	db *storage.DB,
	diskPath string,
	version string,
	clock platform.Clock,
	backups BackupProvider,
) (*Service, error) {
	if db == nil || db.Reader == nil || db.Writer == nil ||
		db.Path == "" || diskPath == "" || version == "" ||
		clock == nil {
		return nil, errors.New("health service unavailable")
	}
	return &Service{
		db: db, databasePath: filepath.Dir(db.Path),
		backupDiskPath: diskPath, version: safeVersion(version),
		clock: clock, startedAt: clock.Now().UTC(), backups: backups,
	}, nil
}

func (s *Service) SetMaintenance(provider StatusProvider) {
	if s != nil {
		s.maintenance = provider
	}
}

func (s *Service) Liveness() Liveness {
	return Liveness{Status: "ok"}
}

func (s *Service) Detailed(ctx context.Context) (Detail, error) {
	if s == nil || ctx == nil {
		return Detail{}, errors.New("health service unavailable")
	}
	detail := Detail{
		Status: "ok", Version: s.version, Database: "ok",
	}
	now := s.clock.Now().UTC()
	if now.After(s.startedAt) {
		detail.UptimeSeconds = int64(now.Sub(s.startedAt) / time.Second)
	}
	if err := s.db.Reader.PingContext(ctx); err != nil {
		return Detail{}, errors.New("health service unavailable")
	}
	if err := s.db.Reader.QueryRowContext(
		ctx, `PRAGMA journal_mode`,
	).Scan(&detail.JournalMode); err != nil {
		return Detail{}, errors.New("health service unavailable")
	}
	detail.JournalMode = strings.ToLower(detail.JournalMode)
	if detail.JournalMode != "wal" {
		detail.Status = "degraded"
		detail.Database = "degraded"
	}
	database, err := s.probeWriter(ctx)
	if err != nil {
		return Detail{}, err
	}
	if database != "ok" {
		detail.Status = "degraded"
		detail.Database = database
	}
	if err := s.db.Reader.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(version), 0) FROM schema_migrations
	`).Scan(&detail.MigrationVersion); err != nil {
		return Detail{}, errors.New("health service unavailable")
	}
	databaseFree, err := diskFreeBytes(s.databasePath)
	if err != nil {
		return Detail{}, errors.New("health service unavailable")
	}
	backupFree, err := diskFreeBytes(s.backupDiskPath)
	if err != nil {
		return Detail{}, errors.New("health service unavailable")
	}
	detail.DatabaseDiskFreeBytes = databaseFree
	detail.BackupDiskFreeBytes = backupFree

	if s.backups != nil {
		latest, err := s.backups.LatestSuccessful(ctx)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return Detail{}, errors.New("health service unavailable")
		}
		if latest != nil {
			detail.LastBackup = &BackupSummary{
				ID: latest.ID, Status: latest.Status,
				SizeBytes: latest.SizeBytes, CompletedAt: latest.CompletedAt,
				Retained:              latest.Retained,
				VerificationStatus:    latest.VerificationStatus,
				VerifiedAt:            latest.VerifiedAt,
				VerificationErrorCode: latest.VerificationErrorCode,
			}
			if latest.VerificationStatus != "passed" {
				detail.Status = "degraded"
			}
		} else {
			detail.Status = "degraded"
		}
	}
	if s.maintenance != nil {
		status := s.maintenance.Status()
		status.ErrorCodes = append([]string(nil), status.ErrorCodes...)
		detail.Maintenance = &status
		if len(status.ErrorCodes) > 0 {
			detail.Status = "degraded"
		}
	}
	return detail, nil
}

func (s *Service) probeWriter(ctx context.Context) (string, error) {
	tx, err := s.db.Writer.BeginTx(ctx, nil)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return classifyWriteFailure(err), nil
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(
		ctx, `UPDATE health_probe SET marker = marker WHERE id = 1`,
	); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return classifyWriteFailure(err), nil
	}
	if err := tx.Rollback(); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "unavailable", nil
	}
	return "ok", nil
}

func classifyWriteFailure(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "readonly"),
		strings.Contains(message, "read-only"):
		return "readonly"
	case strings.Contains(message, "busy"),
		strings.Contains(message, "locked"):
		return "busy"
	default:
		return "unavailable"
	}
}

func diskFreeBytes(path string) (uint64, error) {
	var filesystem unix.Statfs_t
	if err := unix.Statfs(path, &filesystem); err != nil {
		return 0, err
	}
	return uint64(filesystem.Bavail) * uint64(filesystem.Bsize), nil
}

func safeVersion(value string) string {
	if len(value) == 0 || len(value) > 64 {
		return "unknown"
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			!strings.ContainsRune(".+-_", character) {
			return "unknown"
		}
	}
	return value
}
