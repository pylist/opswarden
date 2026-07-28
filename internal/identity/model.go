package identity

import (
	"errors"
	"net/netip"
	"time"
)

const (
	SystemRoleOwner  = "system_owner"
	SystemRoleAdmin  = "system_admin"
	SystemRoleMember = "member"

	RecoveryCodeCount       = 10
	TOTPPeriod              = 30 * time.Second
	LoginChallengeLifetime  = 5 * time.Minute
	SessionIdleLifetime     = 8 * time.Hour
	SessionAbsoluteLifetime = 24 * time.Hour
	RecentTOTPLifetime      = 5 * time.Minute
)

var (
	ErrInitialOwnerSourceDenied = errors.New("initial owner source is not allowed")
	ErrInitialOwnerExists       = errors.New("initial owner already exists")
	ErrInvalidOwnerInput        = errors.New("invalid initial owner input")
	ErrInvalidCredentials       = errors.New("invalid credentials")
	ErrInvalidChallenge         = errors.New("invalid login challenge")
	ErrInvalidTOTP              = errors.New("invalid TOTP")
	ErrTOTPReplay               = errors.New("TOTP code was already used")
	ErrInvalidRecoveryCode      = errors.New("invalid recovery code")
	ErrInvalidSession           = errors.New("invalid session")
	ErrSessionExpired           = errors.New("session expired")
	ErrSessionRevoked           = errors.New("session revoked")
	ErrUserNotFound             = errors.New("user not found")
	ErrForbidden                = errors.New("identity operation forbidden")
	ErrInvalidSystemRole        = errors.New("invalid system role")
	ErrRecentTOTPRequired       = errors.New("recent TOTP verification required")
	ErrLastSystemOwner          = errors.New("at least one active System Owner is required")
)

type Config struct {
	InternalCIDRs []netip.Prefix
}

type CreateOwnerInput struct {
	Email    string
	Password string
	TOTPSeed string
	SourceIP netip.Addr
}

type CreateOwnerResult struct {
	UserID        string
	RecoveryCodes []string
}

type LoginChallenge struct {
	ID        string
	ExpiresAt time.Time
}

type Session struct {
	RawToken      string
	ExpiresAt     time.Time
	IdleExpiresAt time.Time
}

type SessionPrincipal struct {
	UserID       string
	SessionID    string
	IssuedAt     time.Time
	RecentTOTPAt time.Time
}

func (p SessionPrincipal) HasRecentTOTP(now time.Time) bool {
	if p.RecentTOTPAt.IsZero() || now.Before(p.RecentTOTPAt) {
		return false
	}
	return now.Sub(p.RecentTOTPAt) < RecentTOTPLifetime
}
