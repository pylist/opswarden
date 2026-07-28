package apierrors

import (
	"errors"
	"net/http"

	"opswarden/internal/agents"
	"opswarden/internal/assets"
	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/credentials"
	"opswarden/internal/identity"
	"opswarden/internal/spaces"
)

type Code string

const (
	CodeInvalidRequest      Code = "INVALID_REQUEST"
	CodeUnauthenticated     Code = "UNAUTHENTICATED"
	CodePermissionDenied    Code = "PERMISSION_DENIED"
	CodeNotFound            Code = "NOT_FOUND"
	CodeVersionConflict     Code = "VERSION_CONFLICT"
	CodeIdempotencyConflict Code = "IDEMPOTENCY_CONFLICT"
	CodeStorageBusy         Code = "STORAGE_BUSY"
	CodeStorageUnavailable  Code = "STORAGE_UNAVAILABLE"
	CodeInternalError       Code = "INTERNAL_ERROR"
)

type Classification struct {
	Code      Code
	Status    int
	Retryable bool
}

type sqliteCoder interface {
	Code() int
}

const (
	sqliteBusy   = 5
	sqliteLocked = 6
)

// Classify maps domain and storage errors to the stable public error contract.
// It deliberately does not inspect error messages, which may contain secrets or
// change across SQLite driver versions.
func Classify(err error) Classification {
	switch {
	case err == nil:
		return Classification{}
	case isSQLiteBusy(err):
		return Classification{
			Code: CodeStorageBusy, Status: http.StatusServiceUnavailable,
			Retryable: true,
		}
	case errors.Is(err, authorization.ErrUnauthenticated),
		errors.Is(err, identity.ErrInvalidSession),
		errors.Is(err, identity.ErrSessionExpired),
		errors.Is(err, identity.ErrSessionRevoked),
		errors.Is(err, identity.ErrInvalidCredentials),
		errors.Is(err, identity.ErrInvalidChallenge),
		errors.Is(err, identity.ErrInvalidTOTP),
		errors.Is(err, identity.ErrTOTPReplay),
		errors.Is(err, identity.ErrInvalidRecoveryCode),
		errors.Is(err, agents.ErrAuthenticationFailed),
		errors.Is(err, agents.ErrUnauthenticated),
		errors.Is(err, spaces.ErrUnauthenticated):
		return Classification{
			Code: CodeUnauthenticated, Status: http.StatusUnauthorized,
		}
	case errors.Is(err, credentials.ErrInvalidInput),
		errors.Is(err, credentials.ErrInvalidPayload),
		errors.Is(err, credentials.ErrIdempotencyRequired),
		errors.Is(err, credentials.ErrReasonRequired),
		errors.Is(err, assets.ErrInvalidInput),
		errors.Is(err, assets.ErrInvalidCursor),
		errors.Is(err, agents.ErrInvalidInput),
		errors.Is(err, agents.ErrIdempotencyRequired),
		errors.Is(err, agents.ErrInvalidGrant),
		errors.Is(err, agents.ErrInvalidScope),
		errors.Is(err, spaces.ErrInvalidName),
		errors.Is(err, spaces.ErrInvalidRole),
		errors.Is(err, identity.ErrInvalidOwnerInput),
		errors.Is(err, audit.ErrInvalidFilter),
		errors.Is(err, audit.ErrInvalidCursor):
		return Classification{
			Code: CodeInvalidRequest, Status: http.StatusBadRequest,
		}
	case errors.Is(err, credentials.ErrVersionConflict),
		errors.Is(err, assets.ErrVersionConflict),
		errors.Is(err, spaces.ErrVersionConflict),
		errors.Is(err, spaces.ErrMembershipExists),
		errors.Is(err, identity.ErrInitialOwnerExists):
		return Classification{
			Code: CodeVersionConflict, Status: http.StatusConflict,
		}
	case errors.Is(err, credentials.ErrIdempotencyConflict),
		errors.Is(err, agents.ErrIdempotencyConflict):
		return Classification{
			Code: CodeIdempotencyConflict, Status: http.StatusConflict,
		}
	case errors.Is(err, credentials.ErrNotFound),
		errors.Is(err, assets.ErrNotFound),
		errors.Is(err, assets.ErrCrossSpaceLink),
		errors.Is(err, agents.ErrAgentNotFound),
		errors.Is(err, agents.ErrTokenNotFound),
		errors.Is(err, spaces.ErrNotFound),
		errors.Is(err, spaces.ErrMembershipNotFound),
		errors.Is(err, spaces.ErrUserNotFound),
		errors.Is(err, authorization.ErrNotFound):
		return Classification{Code: CodeNotFound, Status: http.StatusNotFound}
	case errors.Is(err, authorization.ErrDenied),
		errors.Is(err, identity.ErrForbidden),
		errors.Is(err, identity.ErrRecentTOTPRequired),
		errors.Is(err, identity.ErrInitialOwnerSourceDenied),
		errors.Is(err, agents.ErrForbidden),
		errors.Is(err, spaces.ErrForbidden),
		errors.Is(err, spaces.ErrLastOwner):
		return Classification{
			Code: CodePermissionDenied, Status: http.StatusForbidden,
		}
	case errors.Is(err, audit.ErrAuditUnavailable),
		errors.Is(err, assets.ErrUnavailable),
		errors.Is(err, agents.ErrAuthenticationUnavailable):
		return Classification{
			Code: CodeStorageUnavailable, Status: http.StatusServiceUnavailable,
			Retryable: true,
		}
	default:
		return Classification{
			Code: CodeInternalError, Status: http.StatusInternalServerError,
		}
	}
}

func isSQLiteBusy(err error) bool {
	var coded sqliteCoder
	if !errors.As(err, &coded) {
		return false
	}
	switch coded.Code() & 0xff {
	case sqliteBusy, sqliteLocked:
		return true
	default:
		return false
	}
}
