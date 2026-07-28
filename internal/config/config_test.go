package config

import (
	"errors"
	"testing"
)

func TestLoadRejectsMissingDataDir(t *testing.T) {
	t.Setenv("OPSWARDEN_DATA_DIR", "")
	t.Setenv("OPSWARDEN_MASTER_KEY_FILE", "/run/secrets/opswarden-master-key")

	_, err := Load()
	if !errors.Is(err, ErrDataDirRequired) {
		t.Fatalf("got %v", err)
	}
}

func TestLoadRejectsMissingMasterKeyFile(t *testing.T) {
	t.Setenv("OPSWARDEN_DATA_DIR", t.TempDir())
	t.Setenv("OPSWARDEN_MASTER_KEY_FILE", "")

	_, err := Load()
	if !errors.Is(err, ErrMasterKeyFileRequired) {
		t.Fatalf("got %v", err)
	}
}
