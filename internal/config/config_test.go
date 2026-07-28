package config

import (
	"errors"
	"testing"
)

func TestLoadRejectsMissingDataDir(t *testing.T) {
	t.Setenv("OPSWARDEN_DATA_DIR", "")

	_, err := Load()
	if !errors.Is(err, ErrDataDirRequired) {
		t.Fatalf("got %v", err)
	}
}
