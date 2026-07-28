package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"opswarden/internal/agents"
	"opswarden/internal/assets"
	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/credentials"
	"opswarden/internal/identity"
	"opswarden/internal/spaces"
)

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	RequestID string         `json:"requestId"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details,omitempty"`
}

var errorMessages = map[string]string{
	"INVALID_REQUEST":        "The request is invalid.",
	"UNAUTHENTICATED":        "Authentication is required.",
	"PERMISSION_DENIED":      "The operation is not permitted.",
	"NOT_FOUND":              "The requested resource was not found.",
	"VERSION_CONFLICT":       "The resource changed since it was read.",
	"IDEMPOTENCY_CONFLICT":   "The idempotency key was reused for another request.",
	"RATE_LIMITED":           "Too many requests.",
	"CREDENTIAL_DELETED":     "The credential is in the recycle bin.",
	"STORAGE_BUSY":           "Storage is temporarily busy.",
	"STORAGE_UNAVAILABLE":    "Storage is unavailable.",
	"MASTER_KEY_UNAVAILABLE": "The master key is unavailable.",
	"INTERNAL_ERROR":         "An internal error occurred.",
}

func writeAPIError(
	writer http.ResponseWriter,
	request *http.Request,
	status int,
	code string,
	retryable bool,
	details map[string]any,
) {
	message := errorMessages[code]
	if message == "" {
		code = "INTERNAL_ERROR"
		message = errorMessages[code]
		status = http.StatusInternalServerError
		retryable = false
		details = nil
	}
	writeJSON(writer, status, errorEnvelope{Error: apiError{
		Code: code, Message: message, RequestID: requestID(request.Context()),
		Retryable: retryable, Details: details,
	}})
}

func writeDomainError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case err == nil:
		return
	case errors.Is(err, authorization.ErrUnauthenticated),
		errors.Is(err, identity.ErrInvalidSession),
		errors.Is(err, identity.ErrSessionExpired),
		errors.Is(err, identity.ErrSessionRevoked),
		errors.Is(err, identity.ErrInvalidCredentials),
		errors.Is(err, identity.ErrInvalidChallenge),
		errors.Is(err, identity.ErrInvalidTOTP),
		errors.Is(err, agents.ErrAuthenticationFailed),
		errors.Is(err, agents.ErrUnauthenticated),
		errors.Is(err, spaces.ErrUnauthenticated):
		writeAPIError(writer, request, http.StatusUnauthorized, "UNAUTHENTICATED", false, nil)
	case errors.Is(err, credentials.ErrInvalidInput),
		errors.Is(err, credentials.ErrInvalidPayload),
		errors.Is(err, credentials.ErrIdempotencyRequired),
		errors.Is(err, credentials.ErrReasonRequired),
		errors.Is(err, assets.ErrInvalidInput),
		errors.Is(err, assets.ErrInvalidCursor),
		errors.Is(err, agents.ErrInvalidInput),
		errors.Is(err, agents.ErrInvalidGrant),
		errors.Is(err, agents.ErrInvalidScope),
		errors.Is(err, spaces.ErrInvalidName),
		errors.Is(err, spaces.ErrInvalidRole),
		errors.Is(err, audit.ErrInvalidFilter),
		errors.Is(err, audit.ErrInvalidCursor):
		writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
	case errors.Is(err, credentials.ErrVersionConflict),
		errors.Is(err, assets.ErrVersionConflict):
		writeAPIError(writer, request, http.StatusConflict, "VERSION_CONFLICT", false, nil)
	case errors.Is(err, credentials.ErrIdempotencyConflict):
		writeAPIError(writer, request, http.StatusConflict, "IDEMPOTENCY_CONFLICT", false, nil)
	case errors.Is(err, credentials.ErrNotFound),
		errors.Is(err, assets.ErrNotFound),
		errors.Is(err, assets.ErrCrossSpaceLink),
		errors.Is(err, agents.ErrAgentNotFound),
		errors.Is(err, agents.ErrTokenNotFound),
		errors.Is(err, spaces.ErrNotFound),
		errors.Is(err, spaces.ErrMembershipNotFound),
		errors.Is(err, spaces.ErrUserNotFound),
		errors.Is(err, authorization.ErrNotFound):
		writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
	case errors.Is(err, authorization.ErrDenied),
		errors.Is(err, identity.ErrForbidden),
		errors.Is(err, identity.ErrRecentTOTPRequired),
		errors.Is(err, agents.ErrForbidden),
		errors.Is(err, spaces.ErrForbidden):
		writeAPIError(writer, request, http.StatusForbidden, "PERMISSION_DENIED", false, nil)
	case errors.Is(err, audit.ErrAuditUnavailable),
		errors.Is(err, assets.ErrUnavailable),
		errors.Is(err, agents.ErrAuthenticationUnavailable):
		writeAPIError(writer, request, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", true, nil)
	default:
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "busy") || strings.Contains(message, "locked") {
			writeAPIError(writer, request, http.StatusServiceUnavailable, "STORAGE_BUSY", true, nil)
			return
		}
		writeAPIError(writer, request, http.StatusInternalServerError, "INTERNAL_ERROR", false, nil)
	}
}
