package credentials

import (
	"encoding/json"
	"errors"
	"time"

	"opswarden/internal/audit"
	"opswarden/internal/authorization"
)

type Type string

const (
	TypeLogin    Type = "login"
	TypeAPIToken Type = "api_token"
	TypeSSHKey   Type = "ssh_key"
	TypeDatabase Type = "database"
	TypeTOTP     Type = "totp"
)

func (credentialType Type) Valid() bool {
	switch credentialType {
	case TypeLogin, TypeAPIToken, TypeSSHKey, TypeDatabase, TypeTOTP:
		return true
	default:
		return false
	}
}

var (
	ErrInvalidInput        = errors.New("invalid credential input")
	ErrInvalidPayload      = errors.New("invalid credential payload")
	ErrNotFound            = errors.New("credential not found")
	ErrVersionConflict     = errors.New("credential version conflict")
	ErrIdempotencyRequired = errors.New("idempotency key is required")
	ErrIdempotencyConflict = errors.New("idempotency key was reused for a different request")
	ErrReasonRequired      = errors.New("agent mutation reason is required")
	ErrAuditUnavailable    = audit.ErrAuditUnavailable
)

type Principal struct {
	Human        *authorization.HumanPrincipal
	Agent        *authorization.AgentPrincipal
	BoundSpaceID string
	Actor        audit.Actor
	RequestID    string
	SourceIP     string
	UserAgent    string
}

type WriteContext struct {
	Actor          audit.Actor
	IdempotencyKey string
	Reason         string
}

type CreateInput struct {
	SpaceID     string
	DisplayName string
	Type        Type
	Tags        map[string]string
	AssetIDs    []string
	Payload     json.RawMessage
}

type UpdateInput struct {
	CredentialID    string
	ExpectedVersion uint64
	DisplayName     *string
	Tags            map[string]string
	AssetIDs        []string
	Payload         json.RawMessage
}

type Metadata struct {
	ID          string
	SpaceID     string
	DisplayName string
	Type        Type
	Version     uint64
	Tags        map[string]string
	AssetIDs    []string
	DeletedAt   *time.Time
}

type Decrypted struct {
	Metadata Metadata
	Payload  json.RawMessage
}

type MutationResult struct {
	ID      string
	Version uint64
	Status  int
}

type ListFilter struct {
	SpaceID        string
	Type           Type
	Tags           map[string]string
	IncludeDeleted bool
	DeletedOnly    bool
	After          string
	Limit          int
}
