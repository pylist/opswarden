package maintenance

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"opswarden/internal/backup"
	"opswarden/internal/health"
	"opswarden/internal/platform"
	"opswarden/internal/storage"
)

const DailyInterval = 24 * time.Hour

type BackupService interface {
	Run(context.Context) (string, error)
	ApplyRetention(context.Context) ([]backup.RunRecord, error)
}

type AuditPurger interface {
	PurgeBefore(context.Context, time.Time) (int64, error)
}

type CredentialPurger interface {
	PurgeExpiredMaintenance(context.Context, time.Time) (int64, error)
}

type Ticker interface {
	C() <-chan time.Time
	Stop()
}

type TickerFactory interface {
	NewTicker(time.Duration) Ticker
}

type systemTicker struct{ *time.Ticker }

func (ticker systemTicker) C() <-chan time.Time { return ticker.Ticker.C }

type SystemTickerFactory struct{}

func (SystemTickerFactory) NewTicker(duration time.Duration) Ticker {
	return systemTicker{Ticker: time.NewTicker(duration)}
}

type Scheduler struct {
	db                    *storage.DB
	backups               BackupService
	audit                 AuditPurger
	credentials           CredentialPurger
	clock                 platform.Clock
	tickers               TickerFactory
	auditRetentionEnabled bool

	lifecycleMu sync.Mutex
	started     bool
	cancel      context.CancelFunc
	done        chan struct{}

	runMu    sync.Mutex
	statusMu sync.RWMutex
	status   health.MaintenanceStatus
}

func NewScheduler(
	db *storage.DB,
	backups BackupService,
	audit AuditPurger,
	credentials CredentialPurger,
	clock platform.Clock,
	tickers TickerFactory,
	auditRetentionEnabled bool,
) (*Scheduler, error) {
	if db == nil || db.Writer == nil || backups == nil || audit == nil ||
		credentials == nil ||
		clock == nil {
		return nil, errors.New("maintenance unavailable")
	}
	if tickers == nil {
		tickers = SystemTickerFactory{}
	}
	return &Scheduler{
		db: db, backups: backups, audit: audit, credentials: credentials,
		clock: clock, tickers: tickers,
		auditRetentionEnabled: auditRetentionEnabled,
		status: health.MaintenanceStatus{
			ErrorCodes: []string{}, AuditRetention: auditRetentionEnabled,
		},
	}, nil
}

func (s *Scheduler) Start(parent context.Context) error {
	if s == nil || parent == nil {
		return errors.New("maintenance unavailable")
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.started {
		return errors.New("maintenance already started")
	}
	ctx, cancel := context.WithCancel(parent)
	s.started = true
	s.cancel = cancel
	s.done = make(chan struct{})
	now := s.clock.Now().UTC()
	s.statusMu.Lock()
	s.status.NextRunAt = now.Add(DailyInterval)
	s.statusMu.Unlock()
	go s.loop(ctx, s.done)
	return nil
}

func (s *Scheduler) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := s.tickers.NewTicker(DailyInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			_ = s.RunOnce(ctx)
			s.statusMu.Lock()
			s.status.NextRunAt = s.clock.Now().UTC().Add(DailyInterval)
			s.statusMu.Unlock()
		}
	}
}

func (s *Scheduler) Stop() {
	if s == nil {
		return
	}
	s.lifecycleMu.Lock()
	if !s.started {
		s.lifecycleMu.Unlock()
		return
	}
	cancel, done := s.cancel, s.done
	s.started = false
	s.cancel = nil
	s.done = nil
	s.lifecycleMu.Unlock()
	cancel()
	<-done
	s.statusMu.Lock()
	s.status.NextRunAt = time.Time{}
	s.statusMu.Unlock()
}

func (s *Scheduler) RunOnce(ctx context.Context) error {
	if s == nil || ctx == nil {
		return errors.New("maintenance unavailable")
	}
	if !s.runMu.TryLock() {
		return errors.New("maintenance already running")
	}
	defer s.runMu.Unlock()
	started := s.clock.Now().UTC()
	s.statusMu.Lock()
	s.status.Running = true
	s.status.LastStartedAt = started
	s.status.ErrorCodes = []string{}
	s.statusMu.Unlock()

	var codes []string
	if _, err := s.backups.Run(ctx); err != nil {
		codes = append(codes, "BACKUP_FAILED")
	}
	if _, err := s.backups.ApplyRetention(ctx); err != nil {
		codes = append(codes, "RETENTION_FAILED")
	}
	if _, err := s.credentials.PurgeExpiredMaintenance(
		ctx, started.Add(-30*24*time.Hour),
	); err != nil {
		codes = append(codes, "CREDENTIAL_PURGE_FAILED")
	}
	if s.auditRetentionEnabled {
		if _, err := s.audit.PurgeBefore(
			ctx, started.UTC().AddDate(-1, 0, 0),
		); err != nil {
			codes = append(codes, "AUDIT_PURGE_FAILED")
		}
	}
	if _, err := s.cleanupExpiredState(ctx, started); err != nil {
		codes = append(codes, "STATE_CLEANUP_FAILED")
	}

	finished := s.clock.Now().UTC()
	if finished.Before(started) {
		finished = started
	}
	s.statusMu.Lock()
	s.status.Running = false
	s.status.LastFinishedAt = finished
	s.status.ErrorCodes = append([]string(nil), codes...)
	if len(codes) == 0 {
		s.status.LastSuccessAt = finished
	}
	s.statusMu.Unlock()
	if len(codes) != 0 {
		return errors.New("maintenance partially failed")
	}
	return nil
}

func (s *Scheduler) Status() health.MaintenanceStatus {
	if s == nil {
		return health.MaintenanceStatus{ErrorCodes: []string{}}
	}
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	result := s.status
	result.ErrorCodes = append([]string(nil), result.ErrorCodes...)
	return result
}

func (s *Scheduler) cleanupExpiredState(
	ctx context.Context,
	now time.Time,
) (int64, error) {
	formatted := now.UTC().Format(time.RFC3339Nano)
	var total int64
	err := storage.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		statements := []string{
			`DELETE FROM sessions
			 WHERE expires_at <= ? OR idle_expires_at <= ?
			    OR (revoked_at IS NOT NULL AND revoked_at <= ?)`,
			`DELETE FROM idempotency_records WHERE expires_at <= ?`,
			`DELETE FROM human_agent_idempotency_records WHERE expires_at <= ?`,
		}
		for index, statement := range statements {
			args := []any{formatted}
			if index == 0 {
				args = []any{formatted, formatted, formatted}
			}
			result, err := tx.ExecContext(ctx, statement, args...)
			if err != nil {
				return err
			}
			affected, err := result.RowsAffected()
			if err != nil {
				return err
			}
			total += affected
		}
		return nil
	})
	return total, err
}
