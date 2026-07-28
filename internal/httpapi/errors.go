package httpapi

import (
	"net/http"

	"opswarden/internal/apierrors"
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
	if err == nil {
		return
	}
	classification := apierrors.Classify(err)
	writeAPIError(
		writer, request, classification.Status, string(classification.Code),
		classification.Retryable, nil,
	)
}
