package app

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"time"

	"opswarden/internal/config"
	"opswarden/internal/storage"
	"opswarden/internal/webui"
)

type App struct {
	handler http.Handler
	server  *http.Server
	db      *storage.DB
}

func New(cfg config.Config) (*App, error) {
	db, err := storage.Open(filepath.Join(cfg.DataDir, "opswarden.db"))
	if err != nil {
		return nil, err
	}
	handler := webui.Handler()
	return &App{
		handler: handler,
		db:      db,
		server: &http.Server{
			Addr:    cfg.ListenAddr,
			Handler: handler,
		},
	}, nil
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
