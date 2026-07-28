package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/identity"
)

const maxGrantJSONBytes = 16 * 1024

var (
	ErrInvalidInput              = errors.New("invalid agent input")
	ErrInvalidScope              = errors.New("invalid agent scope")
	ErrInvalidGrant              = errors.New("invalid agent grant")
	ErrAgentNotFound             = errors.New("agent not found")
	ErrAgentDisabled             = errors.New("agent is disabled")
	ErrTokenNotFound             = errors.New("agent token not found")
	ErrInvalidToken              = errors.New("invalid agent token")
	ErrTokenRevoked              = errors.New("agent token is revoked")
	ErrTokenExpired              = errors.New("agent token is expired")
	ErrInvalidClock              = errors.New("agent authentication clock is invalid")
	ErrAuthenticationFailed      = errors.New("agent authentication failed")
	ErrAuthenticationUnavailable = errors.New("agent authentication unavailable")
	ErrUnauthenticated           = errors.New("agent operation is unauthenticated")
	ErrForbidden                 = errors.New("agent operation is forbidden")
	ErrAuditUnavailable          = audit.ErrAuditUnavailable
	ErrIdempotencyRequired       = errors.New("agent management idempotency key is required")
	ErrIdempotencyConflict       = errors.New("agent management idempotency conflict")
)

type authenticationError struct {
	reason error
}

func (err authenticationError) Error() string {
	return ErrAuthenticationFailed.Error()
}

func (err authenticationError) Is(target error) bool {
	return target == ErrAuthenticationFailed || target == err.reason
}

func authenticationFailed(reason error) error {
	return authenticationError{reason: reason}
}

type Agent struct {
	ID        string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type CreateInput struct {
	Name string
}

type IssuedToken struct {
	ID        string
	Prefix    string
	Raw       string
	ExpiresAt time.Time
	Replayed  bool
}

type Grant struct {
	SpaceID        string
	Scopes         []authorization.Scope
	RequiredLabels map[string]string
}

type AuthenticatedPrincipal struct {
	AgentID     string
	TokenID     string
	TokenPrefix string
	Grants      []Grant
}

func (principal AuthenticatedPrincipal) AuthorizationPrincipal() authorization.AgentPrincipal {
	grants := make([]authorization.Grant, 0, len(principal.Grants))
	for _, grant := range principal.Grants {
		scopes := make(map[authorization.Scope]struct{}, len(grant.Scopes))
		for _, scope := range grant.Scopes {
			scopes[scope] = struct{}{}
		}
		grants = append(grants, authorization.Grant{
			SpaceID: grant.SpaceID,
			Scopes:  scopes,
			Labels:  cloneLabels(grant.RequiredLabels),
		})
	}
	return authorization.AgentPrincipal{AgentID: principal.AgentID, Grants: grants}
}

func (principal AuthenticatedPrincipal) AuditActor() audit.Actor {
	sum := sha256.Sum256([]byte(principal.TokenPrefix))
	fingerprint := hex.EncodeToString(sum[:8])
	clear(sum[:])
	return audit.Actor{
		Type: audit.ActorAgent, ID: principal.AgentID, Fingerprint: fingerprint,
	}
}

type Authenticator interface {
	Authenticate(context.Context, string) (AuthenticatedPrincipal, error)
}

type MutationContext struct {
	Session        identity.SessionPrincipal
	Actor          audit.Actor
	RequestID      string
	SourceIP       string
	UserAgent      string
	IdempotencyKey string
}

type Usage struct {
	AgentID      string
	Name         string
	TokenCount   int
	ActiveTokens int
	LastUsedAt   *time.Time
}
