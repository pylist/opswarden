package maintenance

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"opswarden/internal/backup"
	"opswarden/internal/storage"
)

type fixedClock struct{ now time.Time }

func (clock *fixedClock) Now() time.Time { return clock.now }

type fakeBackups struct {
	run       func(context.Context) error
	retention func(context.Context) error
	runCalls  atomic.Int64
	retCalls  atomic.Int64
}

func (fake *fakeBackups) Run(ctx context.Context) (string, error) {
	fake.runCalls.Add(1)
	if fake.run != nil {
		return "", fake.run(ctx)
	}
	return "unused", nil
}

func (fake *fakeBackups) ApplyRetention(
	ctx context.Context,
) ([]backup.RunRecord, error) {
	fake.retCalls.Add(1)
	if fake.retention != nil {
		return nil, fake.retention(ctx)
	}
	return nil, nil
}

type fakeAudit struct {
	calls  atomic.Int64
	cutoff time.Time
	err    error
}

type fakeCredentialPurger struct {
	db    *storage.DB
	calls atomic.Int64
	err   error
}

func (fake *fakeCredentialPurger) PurgeExpiredMaintenance(
	ctx context.Context,
	cutoff time.Time,
	_ string,
) (int64, error) {
	fake.calls.Add(1)
	if fake.err != nil {
		return 0, fake.err
	}
	result, err := fake.db.Writer.ExecContext(ctx, `
		DELETE FROM credentials WHERE deleted_at IS NOT NULL AND deleted_at <= ?
	`, cutoff.Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (fake *fakeAudit) PurgeBefore(
	_ context.Context,
	cutoff time.Time,
) (int64, error) {
	fake.calls.Add(1)
	fake.cutoff = cutoff
	return 0, fake.err
}

type fakeTicker struct{ ticks chan time.Time }

func (ticker *fakeTicker) C() <-chan time.Time { return ticker.ticks }
func (ticker *fakeTicker) Stop()               {}

type fakeTickers struct {
	ticker   *fakeTicker
	duration time.Duration
	calls    atomic.Int64
}

func (factory *fakeTickers) NewTicker(duration time.Duration) Ticker {
	factory.calls.Add(1)
	factory.duration = duration
	return factory.ticker
}

func TestRunOnceContinuesSafeCleanupAfterEarlierFailures(t *testing.T) {
	db := maintenanceDB(t)
	now := time.Date(2026, 7, 29, 2, 0, 0, 0, time.UTC)
	insertExpiredFixtures(t, db, now)
	backups := &fakeBackups{
		run: func(context.Context) error { return errors.New("failed") },
		retention: func(context.Context) error {
			return errors.New("failed")
		},
	}
	audit := &fakeAudit{err: errors.New("failed")}
	scheduler, err := NewScheduler(
		db, backups, audit, &fakeCredentialPurger{db: db},
		&fixedClock{now: now}, nil, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.RunOnce(context.Background()); err == nil {
		t.Fatal("partial failure reported success")
	}
	if backups.runCalls.Load() != 1 || backups.retCalls.Load() != 1 ||
		audit.calls.Load() != 1 {
		t.Fatalf(
			"calls backup=%d retention=%d audit=%d",
			backups.runCalls.Load(), backups.retCalls.Load(), audit.calls.Load(),
		)
	}
	if !audit.cutoff.Equal(now.AddDate(-1, 0, 0)) {
		t.Fatalf("audit cutoff=%s", audit.cutoff)
	}
	for _, table := range []string{
		"credentials", "sessions", "idempotency_records",
		"human_agent_idempotency_records",
	} {
		var count int
		if err := db.Reader.QueryRow(
			"SELECT count(*) FROM " + table,
		).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s rows=%d", table, count)
		}
	}
	status := scheduler.Status()
	if status.Running || len(status.ErrorCodes) != 3 ||
		status.LastSuccessAt.IsZero() == false {
		t.Fatalf("status=%+v", status)
	}
}

func TestSchedulerStartsOnceStopsAndCancelsInFlightRun(t *testing.T) {
	db := maintenanceDB(t)
	now := time.Date(2026, 7, 29, 2, 0, 0, 0, time.UTC)
	started := make(chan struct{})
	backups := &fakeBackups{
		run: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		},
	}
	ticker := &fakeTicker{ticks: make(chan time.Time, 1)}
	factory := &fakeTickers{ticker: ticker}
	scheduler, err := NewScheduler(
		db, backups, &fakeAudit{}, &fakeCredentialPurger{db: db},
		&fixedClock{now: now}, factory, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Start(context.Background()); err == nil {
		t.Fatal("scheduler started twice")
	}
	ticker.ticks <- now.Add(DailyInterval)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scheduled run did not start")
	}
	stopped := make(chan struct{})
	go func() {
		scheduler.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel and wait for in-flight run")
	}
	if factory.calls.Load() != 1 || factory.duration != DailyInterval {
		t.Fatalf(
			"ticker calls=%d duration=%s", factory.calls.Load(), factory.duration,
		)
	}
	runs := backups.runCalls.Load()
	ticker.ticks <- now.Add(2 * DailyInterval)
	time.Sleep(20 * time.Millisecond)
	if backups.runCalls.Load() != runs {
		t.Fatal("work ran after scheduler stopped")
	}
	if !scheduler.Status().NextRunAt.IsZero() {
		t.Fatal("stopped scheduler retained next run")
	}
}

func TestRunOnceRejectsOverlap(t *testing.T) {
	db := maintenanceDB(t)
	started, release := make(chan struct{}), make(chan struct{})
	backups := &fakeBackups{
		run: func(context.Context) error {
			close(started)
			<-release
			return nil
		},
	}
	scheduler, err := NewScheduler(
		db, backups, &fakeAudit{}, &fakeCredentialPurger{db: db},
		&fixedClock{now: time.Now().UTC()}, nil, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() { first <- scheduler.RunOnce(context.Background()) }()
	<-started
	if err := scheduler.RunOnce(context.Background()); err == nil {
		t.Fatal("overlapping run accepted")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if backups.runCalls.Load() != 1 {
		t.Fatalf("backup calls=%d", backups.runCalls.Load())
	}
}

func TestAuditCutoffUsesExactUTCCalendarYearAcrossLeapDay(t *testing.T) {
	db := maintenanceDB(t)
	now := time.Date(2024, 2, 29, 23, 59, 58, 123, time.FixedZone("plus8", 8*60*60))
	clock := &fixedClock{now: now}
	audit := &fakeAudit{}
	scheduler, err := NewScheduler(
		db, &fakeBackups{}, audit, &fakeCredentialPurger{db: db},
		clock, nil, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := now.UTC().AddDate(-1, 0, 0)
	if !audit.cutoff.Equal(want) || audit.cutoff.Location() != time.UTC {
		t.Fatalf("cutoff=%s want=%s", audit.cutoff, want)
	}
}

func maintenanceDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "opswarden.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func insertExpiredFixtures(t *testing.T, db *storage.DB, now time.Time) {
	t.Helper()
	old := now.Add(-400 * 24 * time.Hour).Format(time.RFC3339Nano)
	if _, err := db.Writer.Exec(`
		INSERT INTO users (
			id, email, normalized_email, password_hash, system_role
		) VALUES ('usr_cleanup', 'cleanup@example.test',
		          'cleanup@example.test', X'01', 'system_owner');
		INSERT INTO spaces (id, name) VALUES ('spc_cleanup', 'Cleanup');
		INSERT INTO credentials (
			id, space_id, name, type, deleted_at
		) VALUES ('cred_cleanup', 'spc_cleanup', 'Old', 'login', ?);
		INSERT INTO sessions (
			id, user_id, token_hash, expires_at, idle_expires_at, revoked_at
		) VALUES ('ses_cleanup', 'usr_cleanup', X'01', ?, ?, ?);
	`, old, old, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer.Exec(`
		INSERT INTO agents (id, name) VALUES ('agt_cleanup', 'Cleanup');
		INSERT INTO idempotency_records (
			id, agent_id, endpoint, key_hash, response_status, created_at,
			expires_at, request_hash, resource_id, resource_version
		) VALUES (
			'idem_cleanup', 'agt_cleanup', '/test', X'01', 200, ?, ?,
			?, 'cred_cleanup', 1
		);
	`, old, old, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer.Exec(`
		INSERT INTO human_agent_idempotency_records (
			id, user_id, endpoint, key_hash, request_hash, resource_id,
			resource_version, response_status, created_at, expires_at
		) VALUES (
			'hidem_cleanup', 'usr_cleanup', '/test', zeroblob(32), ?,
			'agt_cleanup', 1, 200, ?, ?
		)
	`, strings.Repeat("1", 64), old, old); err != nil {
		t.Fatal(err)
	}
}
