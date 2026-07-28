package apierrors

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"opswarden/internal/credentials"
)

type sqliteErrorCode int

func (err sqliteErrorCode) Error() string { return "opaque storage failure" }
func (err sqliteErrorCode) Code() int     { return int(err) }

func TestClassifyStableDomainErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want Classification
	}{
		{
			name: "not found",
			err:  fmt.Errorf("repository: %w", credentials.ErrNotFound),
			want: Classification{Code: CodeNotFound, Status: http.StatusNotFound},
		},
		{
			name: "version conflict",
			err:  credentials.ErrVersionConflict,
			want: Classification{
				Code: CodeVersionConflict, Status: http.StatusConflict,
			},
		},
		{
			name: "idempotency conflict",
			err:  credentials.ErrIdempotencyConflict,
			want: Classification{
				Code: CodeIdempotencyConflict, Status: http.StatusConflict,
			},
		},
		{
			name: "unknown",
			err:  errors.New("unknown"),
			want: Classification{
				Code: CodeInternalError, Status: http.StatusInternalServerError,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Classify(test.err); got != test.want {
				t.Fatalf("Classify() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestClassifySQLiteBusyAndLockedByCode(t *testing.T) {
	t.Parallel()
	want := Classification{
		Code: CodeStorageBusy, Status: http.StatusServiceUnavailable,
		Retryable: true,
	}
	for _, code := range []int{5, 6, 5 | 0x100, 6 | 0x200} {
		err := fmt.Errorf("write transaction: %w", sqliteErrorCode(code))
		if got := Classify(err); got != want {
			t.Fatalf("Classify(code %d) = %#v, want %#v", code, got, want)
		}
	}
}

func TestClassifyDoesNotParseStorageErrorText(t *testing.T) {
	t.Parallel()
	got := Classify(errors.New("database is busy and locked"))
	if got.Code != CodeInternalError {
		t.Fatalf("Classify(text-only error) = %#v, want INTERNAL_ERROR", got)
	}
}
