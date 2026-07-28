package app

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"time"

	"opswarden/internal/agents"
	"opswarden/internal/assets"
	"opswarden/internal/audit"
	"opswarden/internal/backup"
	"opswarden/internal/config"
	"opswarden/internal/credentials"
	"opswarden/internal/cryptobox"
	"opswarden/internal/health"
	"opswarden/internal/httpapi"
	"opswarden/internal/identity"
	"opswarden/internal/maintenance"
	"opswarden/internal/mcpserver"
	"opswarden/internal/platform"
	"opswarden/internal/spaces"
	"opswarden/internal/storage"
	"opswarden/internal/webui"
)

type App struct {
	handler      http.Handler
	server       *http.Server
	db           *storage.DB
	apiCloser    interface{ Close() error }
	backupCloser interface{ Close() error }
	maintenance  *maintenance.Scheduler
}

var Version = "dev"

func New(cfg config.Config) (_ *App, err error) {
	masterKey, err := cryptobox.LoadMasterKey(cfg.MasterKeyFile)
	if err != nil {
		return nil, err
	}
	defer clear(masterKey[:])

	db, err := storage.Open(filepath.Join(cfg.DataDir, "opswarden.db"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, db.Close())
		}
	}()
	box := cryptobox.New(masterKey)
	clock := platform.SystemClock{}
	auditRepository, err := audit.NewRepository(db)
	if err != nil {
		return nil, err
	}
	auditService, err := audit.NewService(auditRepository)
	if err != nil {
		return nil, err
	}
	identityService, err := identity.NewService(
		db, box, clock, identity.Config{
			InternalCIDRs: cfg.InternalCIDRs, Audit: auditRepository,
		},
	)
	if err != nil {
		return nil, err
	}
	spaceService, err := spaces.NewAuditedService(
		db, identityService, auditRepository, clock,
	)
	if err != nil {
		return nil, err
	}
	credentialService, err := credentials.NewService(
		db, box, auditRepository, clock,
	)
	if err != nil {
		return nil, err
	}
	assetService, err := assets.NewService(db, auditRepository, clock)
	if err != nil {
		return nil, err
	}
	agentService, err := agents.NewService(db, auditRepository, clock)
	if err != nil {
		return nil, err
	}
	backupDir := cfg.BackupDir
	defaultBackupDir := filepath.Join(cfg.DataDir, "backups")
	if backupDir == "" || backupDir == defaultBackupDir {
		backupDir = filepath.Join(filepath.Dir(db.Path), "backups")
	}
	backupService, err := backup.NewService(db, backupDir, clock)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, backupService.Close())
		}
	}()
	maintenanceScheduler, err := maintenance.NewScheduler(
		db, backupService, auditService, credentialService, clock, nil,
		!cfg.DisableAuditRetention,
	)
	if err != nil {
		return nil, err
	}
	healthService, err := health.NewService(
		db, backupDir, Version, clock, backupService,
	)
	if err != nil {
		return nil, err
	}
	healthService.SetMaintenance(maintenanceScheduler)
	limiter := agents.NewLimiter(agents.LimiterConfig{})
	apiHandler := httpapi.New(httpapi.Dependencies{
		Identity: identityService, Spaces: spaceService,
		Credentials: credentialService, Assets: assetService,
		Agents: agentService, Audit: auditService, AuthAudit: auditService,
		Backups: backupService, Health: healthService,
		Limiter: limiter, Clock: clock, MasterKey: masterKey,
		TrustedProxyCIDRs: cfg.TrustedProxyCIDRs,
		Fallback:          webui.Handler(),
	})
	mcpHandler, err := mcpserver.New(mcpserver.Dependencies{
		Agents: agentService, Credentials: credentialService,
		Assets: assetService, AuthAudit: auditService,
		Limiter: limiter, Clock: clock,
		TrustedProxyCIDRs: cfg.TrustedProxyCIDRs,
	})
	if err != nil {
		if closer, ok := apiHandler.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("/", apiHandler)
	handler := http.Handler(mux)
	application := &App{
		handler:      handler,
		db:           db,
		backupCloser: backupService,
		maintenance:  maintenanceScheduler,
		server: &http.Server{
			Addr:              cfg.ListenAddr,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    32 << 10,
		},
	}
	application.apiCloser, _ = apiHandler.(interface{ Close() error })
	return application, nil
}

func (a *App) Handler() http.Handler {
	return a.handler
}

func (a *App) Run(ctx context.Context) error {
	if a.maintenance != nil {
		if err := a.maintenance.Start(ctx); err != nil {
			return err
		}
		defer a.maintenance.Stop()
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- a.server.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		return normalizeServerError(err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := a.server.Shutdown(shutdownCtx); err != nil {
			if closeErr := a.server.Close(); closeErr != nil {
				return errors.Join(err, closeErr)
			}
			return err
		}
		return normalizeServerError(<-serveErr)
	}
}

func (a *App) Close() error {
	var errs []error
	if a.maintenance != nil {
		a.maintenance.Stop()
	}
	if a.server != nil {
		errs = append(errs, normalizeServerError(a.server.Close()))
	}
	if a.apiCloser != nil {
		errs = append(errs, a.apiCloser.Close())
	}
	if a.backupCloser != nil {
		errs = append(errs, a.backupCloser.Close())
	}
	if a.db != nil {
		errs = append(errs, a.db.Close())
	}
	return errors.Join(errs...)
}

func normalizeServerError(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
