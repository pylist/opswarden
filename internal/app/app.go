package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	"opswarden/internal/config"
	"opswarden/internal/webui"
)

type App struct {
	handler http.Handler
	server  *http.Server
}

func New(cfg config.Config) (*App, error) {
	handler := webui.Handler()
	return &App{
		handler: handler,
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
	return a.server.Close()
}

func normalizeServerError(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
