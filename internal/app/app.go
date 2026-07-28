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
	"opswarden/internal/config"
	"opswarden/internal/credentials"
	"opswarden/internal/cryptobox"
	"opswarden/internal/httpapi"
	"opswarden/internal/identity"
	"opswarden/internal/platform"
	"opswarden/internal/spaces"
	"opswarden/internal/storage"
	"opswarden/internal/webui"
)

type App struct {
	handler   http.Handler
	server    *http.Server
	db        *storage.DB
	apiCloser interface{ Close() error }
}

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
	handler := httpapi.New(httpapi.Dependencies{
		Identity: identityService, Spaces: spaceService,
		Credentials: credentialService, Assets: assetService,
		Agents: agentService, Audit: auditService, AuthAudit: auditService,
		Clock: clock, MasterKey: masterKey,
		TrustedProxyCIDRs: cfg.TrustedProxyCIDRs,
		Fallback:          webui.Handler(),
	})
	application := &App{
		handler: handler,
		db:      db,
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
	application.apiCloser, _ = handler.(interface{ Close() error })
	return application, nil
}

func (a *App) Handler() http.Handler {
	return a.handler
}

func (a *App) Run(ctx context.Context) error {
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
	if a.server != nil {
		errs = append(errs, normalizeServerError(a.server.Close()))
	}
	if a.apiCloser != nil {
		errs = append(errs, a.apiCloser.Close())
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
