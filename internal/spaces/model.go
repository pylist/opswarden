package spaces

import (
	"errors"
	"time"

	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/identity"
)

type Role = authorization.Role

const (
	Owner  = authorization.RoleOwner
	Editor = authorization.RoleEditor
	Reader = authorization.RoleReader
)

var (
	ErrUnauthenticated    = errors.New("Space principal is not authenticated")
	ErrForbidden          = errors.New("Space operation forbidden")
	ErrNotFound           = errors.New("Space not found")
	ErrInvalidName        = errors.New("invalid Space name")
	ErrInvalidRole        = errors.New("invalid Space role")
	ErrUserNotFound       = errors.New("Space member user not found")
	ErrMembershipExists   = errors.New("Space membership already exists")
	ErrMembershipNotFound = errors.New("Space membership not found")
	ErrLastOwner          = errors.New("at least one Space Owner is required")
)

type Space struct {
	ID        string
	Name      string
	Role      Role
	CreatedAt time.Time
	UpdatedAt time.Time
}

type CreateInput struct {
	Name string
}

type MutationContext struct {
	Session   identity.SessionPrincipal
	Actor     audit.Actor
	RequestID string
	SourceIP  string
	UserAgent string
}
