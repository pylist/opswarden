package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"opswarden/internal/app"
	"opswarden/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	application, err := app.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = application.Run(ctx)
	if err != nil {
		log.Fatal(err)
	}
}
