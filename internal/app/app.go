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
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = a.server.Shutdown(shutdownCtx)
	}()

	err := a.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (a *App) Close() error {
	return a.server.Close()
}
