package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"opswarden/internal/backup"
	"opswarden/internal/health"
	"opswarden/internal/identity"
)

type fakeHealthService struct {
	detail health.Detail
	err    error
}

func (service fakeHealthService) Liveness() health.Liveness {
	return health.Liveness{Status: "ok"}
}

func (service fakeHealthService) Detailed(context.Context) (health.Detail, error) {
	return service.detail, service.err
}

type fakeBackupService struct {
	runs []backup.RunRecord
	err  error
}

func (service fakeBackupService) ListRuns(
	context.Context,
	int,
) ([]backup.RunRecord, error) {
	return service.runs, service.err
}

func TestLivenessIsMinimalStrictAndNoStore(t *testing.T) {
	handler := newTestHandler(Dependencies{
		Health: fakeHealthService{},
		Clock:  &fixedClock{now: time.Now().UTC()},
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(
		response, httptest.NewRequest(http.MethodGet, "/health/live", nil),
	)
	if response.Code != http.StatusOK ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v", response.Code, response.Header())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 1 || body["status"] != "ok" {
		t.Fatalf("liveness=%v", body)
	}
	for _, target := range []string{"/health/live?details=true", "/health/live/"} {
		response = httptest.NewRecorder()
		handler.ServeHTTP(
			response, httptest.NewRequest(http.MethodGet, target, nil),
		)
		if response.Code < 400 {
			t.Fatalf("target=%q status=%d", target, response.Code)
		}
	}
}

func TestAdministrativeHealthAndBackupResponsesAreAuthorizedAndPathFree(t *testing.T) {
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	session := identity.Session{
		RawToken: "opaque-admin-session", ExpiresAt: now.Add(time.Hour),
	}
	principal := identity.SessionPrincipal{
		UserID: "usr_admin", SessionID: "ses_admin", IssuedAt: now,
	}
	identityService := &fakeIdentityService{
		session: session, principal: principal,
	}
	recorder := &recordingAuthAudit{}
	run := backup.RunRecord{
		ID: "bkp_0123456789abcdef0123456789abcdef", Status: "succeeded",
		Filename: "opswarden-20260729T010203.000000000Z-" +
			"bkp_0123456789abcdef0123456789abcdef.sqlite3",
		Checksum: strings.Repeat("a", 64), SizeBytes: 4096,
		StartedAt: now.Add(-time.Second), CompletedAt: now, Retained: true,
	}
	handler := newTestHandler(Dependencies{
		Identity: identityService,
		Spaces:   fakeSpaceService{systemRole: identity.SystemRoleAdmin},
		Health: fakeHealthService{detail: health.Detail{
			Status: "ok", Version: "test", Database: "ok",
			JournalMode: "wal", DatabaseDiskFreeBytes: 1024,
			BackupDiskFreeBytes: 2048, MigrationVersion: 11,
		}},
		Backups:   fakeBackupService{runs: []backup.RunRecord{run}},
		AuthAudit: recorder, Clock: &fixedClock{now: now},
		MasterKey: [32]byte{1},
	})
	token, err := handler.(*Router).jwt.sign(principal.UserID, session)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/api/v1/health", "/api/v1/backups?limit=10"} {
		response := serveAuthorized(handler, token, http.MethodGet, target, nil)
		if response.Code != http.StatusOK {
			t.Fatalf(
				"target=%s status=%d body=%s",
				target, response.Code, response.Body.String(),
			)
		}
		body := strings.ToLower(response.Body.String())
		for _, forbidden := range []string{
			"/var/", "master", "fingerprint", "opaque-admin-session",
		} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("target=%s leaked %q: %s", target, forbidden, body)
			}
		}
	}
	var healthRead, backupList bool
	for _, event := range recorder.events {
		healthRead = healthRead || event.Action == "health.read"
		backupList = backupList || event.Action == "backup.list"
	}
	if !healthRead || !backupList {
		t.Fatalf("audit events=%+v", recorder.events)
	}

	recorder.failAction = "health.read"
	response := serveAuthorized(
		handler, token, http.MethodGet, "/api/v1/health", nil,
	)
	if response.Code != http.StatusServiceUnavailable ||
		strings.Contains(response.Body.String(), `"version":"test"`) {
		t.Fatalf(
			"audit failure returned detail: status=%d body=%s",
			response.Code, response.Body.String(),
		)
	}
}

func TestAdministrativeEndpointsRejectNonAdminAndMalformedQueries(t *testing.T) {
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	session := identity.Session{
		RawToken: "opaque-member-session", ExpiresAt: now.Add(time.Hour),
	}
	principal := identity.SessionPrincipal{
		UserID: "usr_member", SessionID: "ses_member", IssuedAt: now,
	}
	handler := newTestHandler(Dependencies{
		Identity: &fakeIdentityService{session: session, principal: principal},
		Spaces:   fakeSpaceService{},
		Health:   fakeHealthService{},
		Backups:  fakeBackupService{},
		Clock:    &fixedClock{now: now}, MasterKey: [32]byte{1},
	})
	token, err := handler.(*Router).jwt.sign(principal.UserID, session)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/api/v1/health", "/api/v1/backups"} {
		response := serveAuthorized(handler, token, http.MethodGet, target, nil)
		if response.Code != http.StatusForbidden {
			t.Fatalf(
				"target=%s status=%d body=%s",
				target, response.Code, response.Body.String(),
			)
		}
	}
	for _, target := range []string{
		"/api/v1/health?full=true",
		"/api/v1/backups?limit=01",
		"/api/v1/backups?limit=201",
		"/api/v1/backups?limit=10&limit=11",
		"/api/v1/backups?path=/tmp/database",
	} {
		response := serveAuthorized(handler, token, http.MethodGet, target, nil)
		if response.Code != http.StatusBadRequest {
			t.Fatalf(
				"target=%s status=%d body=%s",
				target, response.Code, response.Body.String(),
			)
		}
	}
}
