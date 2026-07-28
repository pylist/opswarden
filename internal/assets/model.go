package assets

import (
	"errors"
	"net/netip"
	"time"

	"opswarden/internal/audit"
	"opswarden/internal/credentials"
)

var (
	ErrInvalidInput     = errors.New("invalid asset input")
	ErrNotFound         = errors.New("asset not found")
	ErrVersionConflict  = errors.New("asset version conflict")
	ErrCrossSpaceLink   = errors.New("asset and credential belong to different Spaces")
	ErrAuditUnavailable = audit.ErrAuditUnavailable
)

type Principal = credentials.Principal

type Asset struct {
	ID          string
	SpaceID     string
	Name        string
	Type        string
	Hostname    string
	OS          string
	Environment string
	Status      string
	IPs         []netip.Addr
	Ports       []uint16
	Tags        map[string]string
	Notes       string
	Version     uint64
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
}

type CreateInput struct {
	SpaceID     string
	Name        string
	Type        string
	Hostname    string
	OS          string
	Environment string
	Status      string
	IPs         []netip.Addr
	Ports       []uint16
	Tags        map[string]string
	Notes       string
}

type UpdateInput struct {
	AssetID         string
	ExpectedVersion uint64
	Name            string
	Type            string
	Hostname        string
	OS              string
	Environment     string
	Status          string
	IPs             []netip.Addr
	Ports           []uint16
	Tags            map[string]string
	Notes           string
}

type ListFilter struct {
	SpaceID     string
	Type        string
	Environment string
	Status      string
	Tags        map[string]string
	Limit       int
}
