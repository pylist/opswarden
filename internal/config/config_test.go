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

func TestLoadParsesCanonicalTrustedProxyCIDRs(t *testing.T) {
	t.Setenv("OPSWARDEN_DATA_DIR", t.TempDir())
	t.Setenv("OPSWARDEN_MASTER_KEY_FILE", "/run/secrets/key")
	t.Setenv("OPSWARDEN_TRUSTED_PROXY_CIDRS", "10.0.0.0/8,fd00::/8")
	config, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(config.TrustedProxyCIDRs) != 2 ||
		config.TrustedProxyCIDRs[0].String() != "10.0.0.0/8" ||
		config.TrustedProxyCIDRs[1].String() != "fd00::/8" {
		t.Fatalf("trusted proxies=%v", config.TrustedProxyCIDRs)
	}
}

func TestLoadRejectsNonCanonicalTrustedProxyCIDRs(t *testing.T) {
	t.Setenv("OPSWARDEN_DATA_DIR", t.TempDir())
	t.Setenv("OPSWARDEN_MASTER_KEY_FILE", "/run/secrets/key")
	t.Setenv("OPSWARDEN_TRUSTED_PROXY_CIDRS", "10.0.0.1/8")
	_, err := Load()
	if !errors.Is(err, ErrTrustedProxyCIDRs) {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadParsesBootstrapInternalCIDRs(t *testing.T) {
	t.Setenv("OPSWARDEN_DATA_DIR", t.TempDir())
	t.Setenv("OPSWARDEN_MASTER_KEY_FILE", "/run/secrets/key")
	t.Setenv("OPSWARDEN_INTERNAL_CIDRS", "10.42.0.0/16")
	config, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(config.InternalCIDRs) != 1 ||
		config.InternalCIDRs[0].String() != "10.42.0.0/16" {
		t.Fatalf("internal CIDRs=%v", config.InternalCIDRs)
	}
}

func TestAuditRetentionDefaultsToOneYearAndCanBeExplicitlyDisabled(t *testing.T) {
	t.Setenv("OPSWARDEN_DATA_DIR", t.TempDir())
	t.Setenv("OPSWARDEN_MASTER_KEY_FILE", "/run/secrets/key")
	t.Setenv("OPSWARDEN_DISABLE_AUDIT_RETENTION", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DisableAuditRetention {
		t.Fatal("one-year audit retention was disabled by default")
	}

	t.Setenv("OPSWARDEN_DISABLE_AUDIT_RETENTION", "true")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DisableAuditRetention {
		t.Fatal("explicit audit retention disable was ignored")
	}
}
