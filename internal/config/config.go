package config

import (
	"errors"
	"net/netip"
	"os"
	"strings"
)

var (
	ErrDataDirRequired       = errors.New("data directory is required")
	ErrMasterKeyFileRequired = errors.New("master key file is required")
	ErrTrustedProxyCIDRs     = errors.New("trusted proxy CIDRs are invalid")
	ErrInternalCIDRs         = errors.New("internal CIDRs are invalid")
)

type Config struct {
	ListenAddr        string
	DataDir           string
	MasterKeyFile     string
	TrustedProxyCIDRs []netip.Prefix
	InternalCIDRs     []netip.Prefix
}

func Load() (Config, error) {
	cfg := Config{
		ListenAddr:    os.Getenv("OPSWARDEN_LISTEN_ADDR"),
		DataDir:       os.Getenv("OPSWARDEN_DATA_DIR"),
		MasterKeyFile: os.Getenv("OPSWARDEN_MASTER_KEY_FILE"),
	}
	trusted, err := parseCIDRs(
		os.Getenv("OPSWARDEN_TRUSTED_PROXY_CIDRS"), ErrTrustedProxyCIDRs,
	)
	if err != nil {
		return Config{}, err
	}
	cfg.TrustedProxyCIDRs = trusted
	internal, err := parseCIDRs(
		os.Getenv("OPSWARDEN_INTERNAL_CIDRS"), ErrInternalCIDRs,
	)
	if err != nil {
		return Config{}, err
	}
	cfg.InternalCIDRs = internal
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

func parseTrustedProxyCIDRs(encoded string) ([]netip.Prefix, error) {
	return parseCIDRs(encoded, ErrTrustedProxyCIDRs)
}

func parseCIDRs(encoded string, invalidError error) ([]netip.Prefix, error) {
	if encoded == "" {
		return nil, nil
	}
	parts := strings.Split(encoded, ",")
	if len(parts) > 16 {
		return nil, invalidError
	}
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(part)
		if err != nil || prefix.Masked() != prefix || prefix.String() != part {
			return nil, invalidError
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}
