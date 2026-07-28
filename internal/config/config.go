package config

import (
	"errors"
	"os"
)

var (
	ErrDataDirRequired       = errors.New("data directory is required")
	ErrMasterKeyFileRequired = errors.New("master key file is required")
)

type Config struct {
	ListenAddr    string
	DataDir       string
	MasterKeyFile string
}

func Load() (Config, error) {
	cfg := Config{
		ListenAddr:    os.Getenv("OPSWARDEN_LISTEN_ADDR"),
		DataDir:       os.Getenv("OPSWARDEN_DATA_DIR"),
		MasterKeyFile: os.Getenv("OPSWARDEN_MASTER_KEY_FILE"),
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	if cfg.DataDir == "" {
		return Config{}, ErrDataDirRequired
	}
	if cfg.MasterKeyFile == "" {
		return Config{}, ErrMasterKeyFileRequired
	}

	return cfg, nil
}
