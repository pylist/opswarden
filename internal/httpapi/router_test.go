package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"opswarden/internal/agents"
	"opswarden/internal/assets"
	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/credentials"
	"opswarden/internal/identity"
	"opswarden/internal/spaces"
	"opswarden/internal/storage"
)

type fixedClock struct {
	now time.Time
}

func (clock *fixedClock) Now() time.Time {
	return clock.now
}

func TestJWTRejectsUnsignedAndExpiredTokens(t *testing.T) {
	clock := &fixedClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	signer, err := newJWTSigner([]byte(strings.Repeat("k", 32)), clock)
	if err != nil {
		t.Fatal(err)
	}
	session := identity.Session{
		RawToken:  "opaque-session-token",
		ExpiresAt: clock.now.Add(identity.SessionAbsoluteLifetime),
	}
	token, err := signer.sign("usr_test", session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.verify(token); err != nil {
		t.Fatalf("verify fresh token: %v", err)
	}

	unsigned := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
		"eyJhdWQiOiJvcHN3YXJkZW4td2ViIiwiZXhwIjoyMDAwMDAwMDAwLCJpYXQiOjE5OTk5OTkxMDAsImlzcyI6Im9wc3dhcmRlbiIsIm5iZiI6MTk5OTk5OTEwMCwic2lkIjoib3BhcXVlLXNlc3Npb24tdG9rZW4iLCJzdWIiOiJ1c3JfdGVzdCJ9."
	if _, err := signer.verify(unsigned); err == nil {
		t.Fatal("alg=none token was accepted")
	}

	clock.now = clock.now.Add(16 * time.Minute)
	if _, err := signer.verify(token); err == nil {
		t.Fatal("expired token was accepted")
	}
}

func TestJWTRejectsAlgorithmClaimAndCanonicalizationConfusion(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	signer, err := newJWTSigner(
		[]byte(strings.Repeat("k", 32)), &fixedClock{now: now},
	)
	if err != nil {
		t.Fatal(err)
	}
	validClaims := fmt.Sprintf(
		`{"iss":"opswarden","aud":"opswarden-web","sub":"usr_test",`+
			`"sid":"opaque","iat":%d,"nbf":%d,"exp":%d}`,
		now.Unix(), now.Unix(), now.Add(10*time.Minute).Unix(),
	)
	tests := []struct {
		name   string
		header string
		claims string
	}{
		{
			name:   "algorithm confusion",
			header: `{"alg":"HS512","typ":"JWT"}`,
			claims: validClaims,
		},
		{
			name:   "wrong issuer",
			header: `{"alg":"HS256","typ":"JWT"}`,
			claims: strings.Replace(validClaims, "opswarden\"", "other\"", 1),
		},
		{
			name:   "future issued at",
			header: `{"alg":"HS256","typ":"JWT"}`,
			claims: fmt.Sprintf(
				`{"iss":"opswarden","aud":"opswarden-web","sub":"usr_test",`+
					`"sid":"opaque","iat":%d,"nbf":%d,"exp":%d}`,
				now.Add(time.Minute).Unix(), now.Add(time.Minute).Unix(),
				now.Add(10*time.Minute).Unix(),
			),
		},
		{
			name:   "duplicate claim",
			header: `{"alg":"HS256","typ":"JWT"}`,
			claims: strings.Replace(
				validClaims, `"iss":"opswarden"`,
				`"iss":"opswarden","iss":"opswarden"`, 1,
			),
		},
		{
			name:   "non canonical JSON",
			header: `{ "alg":"HS256","typ":"JWT"}`,
			claims: validClaims,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := signRawJWTForTest(signer, test.header, test.claims)
			if _, err := signer.verify(token); err == nil {
				t.Fatal("confused token was accepted")
			}
		})
	}
}

func TestNewClearsMasterKeyCopyAfterJWTDerivation(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}
	handler := newTestHandler(Dependencies{
		Clock: &fixedClock{now: time.Now().UTC()}, MasterKey: key,
	})
	router := handler.(*Router)
	for index, value := range router.deps.MasterKey {
		if value != 0 {
			t.Fatalf("retained master key byte %d", index)
		}
	}
}

func signRawJWTForTest(signer *jwtSigner, header, claims string) string {
	unsigned := jwtEncoding.EncodeToString([]byte(header)) + "." +
		jwtEncoding.EncodeToString([]byte(claims))
	mac := hmac.New(sha256.New, signer.key[:])
	_, _ = mac.Write([]byte(unsigned))
	return unsigned + "." + jwtEncoding.EncodeToString(mac.Sum(nil))
}

type fakeIdentityService struct {
	session       identity.Session
	principal     identity.SessionPrincipal
	principals    map[string]identity.SessionPrincipal
	ownerResult   identity.CreateOwnerResult
	ownerInput    identity.CreateOwnerInput
	hasOwner      bool
	ownerCalls    int
	ownerQueries  atomic.Int64
	beginCalls    atomic.Int64
	verifyCalls   atomic.Int64
	beginError    error
	completeError error
	ownerError    error
	verifyError   error
	verifyErrors  map[string]error
	logoutError   error
	resolveError  error
	resolveCalls  atomic.Int64
}

type recordingAuthAudit struct {
	mu         sync.Mutex
	events     []audit.Event
	failAction string
}

func (recorder *recordingAuthAudit) RecordReadBeforeReturn(
	_ context.Context,
	event audit.Event,
) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if event.Action == recorder.failAction {
		return audit.ErrAuditUnavailable
	}
	recorder.events = append(recorder.events, event)
	return nil
}

func (recorder *recordingAuthAudit) eventCount() int {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return len(recorder.events)
}

func newTestHandler(dependencies Dependencies) http.Handler {
	if dependencies.AuthAudit == nil {
		dependencies.AuthAudit = &recordingAuthAudit{}
	}
	return New(dependencies)
}

func (service *fakeIdentityService) BeginLogin(
	context.Context,
	string,
	string,
) (identity.LoginChallenge, error) {
	service.beginCalls.Add(1)
	if service.beginError != nil {
		return identity.LoginChallenge{}, service.beginError
	}
	return identity.LoginChallenge{
		ID: "challenge_test", ExpiresAt: time.Now().Add(time.Minute),
	}, nil
}

func (service *fakeIdentityService) CompleteLogin(
	context.Context,
	string,
	string,
) (identity.Session, error) {
	if service.completeError != nil {
		return identity.Session{}, service.completeError
	}
	return service.session, nil
}

func (service *fakeIdentityService) ResolveSession(
	_ context.Context,
	token string,
) (identity.SessionPrincipal, error) {
	service.resolveCalls.Add(1)
	if service.principals != nil {
		principal, ok := service.principals[token]
		if !ok {
			return identity.SessionPrincipal{}, identity.ErrInvalidSession
		}
		return principal, service.resolveError
	}
	if token != service.session.RawToken {
		return identity.SessionPrincipal{}, identity.ErrInvalidSession
	}
	if service.resolveError != nil {
		return identity.SessionPrincipal{}, service.resolveError
	}
	return service.principal, nil
}

func (service *fakeIdentityService) Logout(context.Context, string) error {
	return service.logoutError
}

func (service *fakeIdentityService) LogoutAudited(
	context.Context,
	string,
	identity.AuthenticationContext,
) error {
	return service.logoutError
}

func (service *fakeIdentityService) CreateInitialOwner(
	_ context.Context,
	input identity.CreateOwnerInput,
) (identity.CreateOwnerResult, error) {
	service.ownerCalls++
	service.ownerInput = input
	return service.ownerResult, service.ownerError
}

func (service *fakeIdentityService) HasInitialOwner(
	context.Context,
) (bool, error) {
	service.ownerQueries.Add(1)
	return service.hasOwner, nil
}

func (service *fakeIdentityService) InitialOwnerSourceAllowed(
	address netip.Addr,
) bool {
	return address.IsValid() && address.IsLoopback()
}

func (service *fakeIdentityService) VerifyRecentTOTPAudited(
	_ context.Context,
	rawToken, code string,
	_ identity.AuthenticationContext,
) (identity.SessionPrincipal, error) {
	service.verifyCalls.Add(1)
	verifyError := service.verifyError
	if service.verifyErrors != nil {
		verifyError = service.verifyErrors[code]
	}
	if service.principals != nil {
		principal, ok := service.principals[rawToken]
		if !ok {
			return identity.SessionPrincipal{}, identity.ErrInvalidSession
		}
		if verifyError != nil {
			return identity.SessionPrincipal{}, verifyError
		}
		return principal, nil
	}
	if rawToken != service.session.RawToken {
		return identity.SessionPrincipal{}, identity.ErrInvalidSession
	}
	if verifyError != nil {
		return identity.SessionPrincipal{}, verifyError
	}
	if service.principal.RecentTOTPAt.IsZero() {
		service.principal.RecentTOTPAt = service.principal.IssuedAt
	}
	return service.principal, nil
}

func TestBootstrapCreatesInitialOwnerOnlyFromRequestSource(t *testing.T) {
	service := &fakeIdentityService{
		ownerResult: identity.CreateOwnerResult{
			UserID: "usr_owner", RecoveryCodes: []string{"recovery"},
		},
	}
	handler := newTestHandler(Dependencies{
		Identity: service, Clock: &fixedClock{now: time.Now().UTC()},
		MasterKey: [32]byte{1},
	})
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/bootstrap/initial-owner",
		strings.NewReader(
			`{"email":"owner@example.test","password":"strong-password",`+
				`"totpSeed":"JBSWY3DPEHPK3PXP"}`,
		),
	)
	request.RemoteAddr = "127.0.0.1:4444"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if service.ownerInput.SourceIP.String() != "127.0.0.1" ||
		service.ownerInput.RequestID == "" {
		t.Fatalf("unsafe bootstrap metadata: %+v", service.ownerInput)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q", got)
	}
}

func TestBootstrapExistingOwnerSkipsExpensiveCreation(t *testing.T) {
	service := &fakeIdentityService{hasOwner: true}
	handler := newTestHandler(Dependencies{
		Identity: service, Clock: &fixedClock{now: time.Now().UTC()},
		MasterKey: [32]byte{1},
	})
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/bootstrap/initial-owner",
		strings.NewReader(
			`{"email":"owner@example.test","password":"strong-password",`+
				`"totpSeed":"JBSWY3DPEHPK3PXP"}`,
		),
	)
	request.RemoteAddr = "127.0.0.1:4444"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if service.ownerCalls != 0 {
		t.Fatalf("existing owner reached expensive create %d times", service.ownerCalls)
	}
	invalid := httptest.NewRequest(
		http.MethodPost, "/api/v1/bootstrap/initial-owner",
		strings.NewReader(
			`{"email":"owner@example.test","password":"strong-password",`+
				`"totpSeed":"not-base32"}`,
		),
	)
	invalid.RemoteAddr = "127.0.0.1:4444"
	invalid.Header.Set("Content-Type", "application/json")
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusBadRequest {
		t.Fatalf(
			"invalid status=%d body=%s",
			invalidResponse.Code, invalidResponse.Body.String(),
		)
	}
}

func TestMissingAuthenticationAuditFailsClosedBeforeAPIDomainWork(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	service := &fakeIdentityService{
		session: identity.Session{
			RawToken: "session", ExpiresAt: now.Add(time.Hour),
		},
		principal: identity.SessionPrincipal{
			UserID: "usr_test", SessionID: "ses_test", IssuedAt: now,
		},
	}
	handler := New(Dependencies{
		Identity: service, Spaces: fakeSpaceService{},
		Clock: &fixedClock{now: now}, MasterKey: [32]byte{1},
	})
	login := postLoginBegin(
		handler,
		`{"email":"owner@example.com","password":"password"}`,
		"127.0.0.1:4242", "",
	)
	if login.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil-audit login status=%d body=%s", login.Code, login.Body.String())
	}
	bootstrap := postBootstrap(handler, "127.0.0.1:4242", 1)
	if bootstrap.Code != http.StatusServiceUnavailable {
		t.Fatalf(
			"nil-audit bootstrap status=%d body=%s",
			bootstrap.Code, bootstrap.Body.String(),
		)
	}
	token, err := handler.(*Router).jwt.sign(
		service.principal.UserID, service.session,
	)
	if err != nil {
		t.Fatal(err)
	}
	protected := serveAuthorized(
		handler, token, http.MethodGet, "/api/v1/me", nil,
	)
	if protected.Code != http.StatusServiceUnavailable {
		t.Fatalf(
			"nil-audit protected status=%d body=%s",
			protected.Code, protected.Body.String(),
		)
	}
	if service.beginCalls.Load() != 0 || service.ownerCalls != 0 ||
		service.ownerQueries.Load() != 0 || service.resolveCalls.Load() != 0 {
		t.Fatalf(
			"domain work escaped nil-audit guard: begin=%d owner=%d queries=%d resolve=%d",
			service.beginCalls.Load(), service.ownerCalls,
			service.ownerQueries.Load(), service.resolveCalls.Load(),
		)
	}
}

func TestExternalBootstrapSourceIsRejectedBeforeOwnerQuery(t *testing.T) {
	service := &fakeIdentityService{hasOwner: true}
	handler := newTestHandler(Dependencies{
		Identity: service, AuthAudit: &recordingAuthAudit{},
		Clock: &fixedClock{now: time.Now().UTC()}, MasterKey: [32]byte{1},
	})
	response := postBootstrap(handler, "198.51.100.80:4242", 1)
	if response.Code != http.StatusForbidden {
		t.Fatalf("external bootstrap status=%d body=%s", response.Code, response.Body.String())
	}
	if queries := service.ownerQueries.Load(); queries != 0 {
		t.Fatalf("external source queried initialization state %d times", queries)
	}
	if service.ownerCalls != 0 {
		t.Fatalf("external source reached owner creation %d times", service.ownerCalls)
	}
}

func TestRecentTOTPVerificationReturnsRenewedJWT(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	service := &fakeIdentityService{
		session: identity.Session{
			RawToken: "opaque-session-token", ExpiresAt: now.Add(time.Hour),
		},
		principal: identity.SessionPrincipal{
			UserID: "usr_test", SessionID: "ses_test", IssuedAt: now,
		},
	}
	handler := newTestHandler(Dependencies{
		Identity: service, Spaces: fakeSpaceService{},
		AuthAudit: &recordingAuthAudit{},
		Clock:     &fixedClock{now: now}, MasterKey: [32]byte{1},
	})
	signer := handler.(*Router).jwt
	token, err := signer.sign("usr_test", service.session)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/auth/reverify",
		strings.NewReader(`{"code":"123456"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Token == "" {
		t.Fatal("step-up did not renew JWT")
	}
	me := serveAuthorized(
		handler, token, http.MethodGet, "/api/v1/me", nil,
	)
	if me.Code != http.StatusOK ||
		!strings.Contains(me.Body.String(), `"recentTotpAt"`) {
		t.Fatalf("fresh /me status=%d body=%s", me.Code, me.Body.String())
	}
	if service.principal.RecentTOTPAt != now || service.resolveCalls.Load() < 2 {
		t.Fatalf(
			"server-side recent TOTP was not observed on renewal: principal=%+v calls=%d",
			service.principal, service.resolveCalls.Load(),
		)
	}
}

func TestReverifySessionQuotaSurvivesSourceRotation(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	service := &fakeIdentityService{
		session: identity.Session{
			RawToken: "stolen-session", ExpiresAt: now.Add(time.Hour),
		},
		principal: identity.SessionPrincipal{
			UserID: "usr_target", SessionID: "ses_target", IssuedAt: now,
		},
		verifyError: identity.ErrInvalidTOTP,
	}
	recorder := &recordingAuthAudit{}
	handler := newTestHandler(Dependencies{
		Identity: service, Spaces: fakeSpaceService{}, AuthAudit: recorder,
		Clock: &fixedClock{now: now}, MasterKey: [32]byte{1},
		Limiter: agents.NewLimiter(agents.LimiterConfig{
			Capacity: map[agents.Operation]int{
				agents.OperationReverifyPrincipal: 2,
				agents.OperationReverifySource:    20,
			},
			RefillPerSecond: map[agents.Operation]float64{
				agents.OperationReverifyPrincipal: 0.000001,
				agents.OperationReverifySource:    0.000001,
			},
		}),
	})
	token, err := handler.(*Router).jwt.sign(
		service.principal.UserID, service.session,
	)
	if err != nil {
		t.Fatal(err)
	}
	for index := range 8 {
		response := postReverify(
			handler, token, "000000",
			fmt.Sprintf("198.51.100.%d:4242", index+100),
		)
		if index < 2 && response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status=%d body=%s", index, response.Code, response.Body.String())
		}
		if index >= 2 && response.Code != http.StatusTooManyRequests {
			t.Fatalf("attempt %d escaped session quota: %d", index, response.Code)
		}
	}
	if calls := service.verifyCalls.Load(); calls != 2 {
		t.Fatalf("TOTP verification calls=%d want 2", calls)
	}
	if events := recorder.eventCount(); events != 4 {
		t.Fatalf("rate-limited attempts wrote individual audits: %d", events)
	}
}

func TestReverifySourceQuotaIsAtomicAndOtherSessionRemainsUsable(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	service := &fakeIdentityService{
		principals: map[string]identity.SessionPrincipal{
			"session-a": {UserID: "usr_a", SessionID: "ses_a", IssuedAt: now},
			"session-b": {UserID: "usr_b", SessionID: "ses_b", IssuedAt: now},
			"session-c": {UserID: "usr_c", SessionID: "ses_c", IssuedAt: now},
		},
		verifyErrors: map[string]error{"000000": identity.ErrInvalidTOTP},
	}
	handler := newTestHandler(Dependencies{
		Identity: service, Spaces: fakeSpaceService{},
		AuthAudit: &recordingAuthAudit{},
		Clock:     &fixedClock{now: now}, MasterKey: [32]byte{1},
		Limiter: agents.NewLimiter(agents.LimiterConfig{
			Capacity: map[agents.Operation]int{
				agents.OperationReverifyPrincipal: 2,
				agents.OperationReverifySource:    2,
			},
			RefillPerSecond: map[agents.Operation]float64{
				agents.OperationReverifyPrincipal: 0.000001,
				agents.OperationReverifySource:    0.000001,
			},
		}),
	})
	tokens := make(map[string]string)
	for raw, principal := range service.principals {
		token, err := handler.(*Router).jwt.sign(principal.UserID, identity.Session{
			RawToken: raw, ExpiresAt: now.Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		tokens[raw] = token
	}
	for _, raw := range []string{"session-a", "session-b"} {
		response := postReverify(
			handler, tokens[raw], "000000", "198.51.100.200:4242",
		)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s status=%d body=%s", raw, response.Code, response.Body.String())
		}
	}
	blocked := postReverify(
		handler, tokens["session-c"], "000000", "198.51.100.200:4242",
	)
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("rotating session escaped source quota: %d", blocked.Code)
	}
	success := postReverify(
		handler, tokens["session-c"], "123456", "198.51.100.201:4242",
	)
	if success.Code != http.StatusOK {
		t.Fatalf(
			"unrelated source history blocked successful step-up: %d %s",
			success.Code, success.Body.String(),
		)
	}
	if calls := service.verifyCalls.Load(); calls != 3 {
		t.Fatalf("TOTP verification calls=%d want 3", calls)
	}
}

func postReverify(
	handler http.Handler,
	token string,
	code string,
	remoteAddr string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/auth/reverify",
		strings.NewReader(`{"code":"`+code+`"}`),
	)
	request.RemoteAddr = remoteAddr
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestLoginReturnsJWTWithoutCookie(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	identityService := &fakeIdentityService{
		session: identity.Session{
			RawToken:  "opaque-session-token",
			ExpiresAt: now.Add(identity.SessionAbsoluteLifetime),
		},
		principal: identity.SessionPrincipal{
			UserID: "usr_test", SessionID: "ses_test", IssuedAt: now,
		},
	}
	handler := newTestHandler(Dependencies{
		Identity: identityService,
		Clock:    &fixedClock{now: now},
		MasterKey: [32]byte{
			1, 2, 3, 4, 5, 6, 7, 8,
			9, 10, 11, 12, 13, 14, 15, 16,
			17, 18, 19, 20, 21, 22, 23, 24,
			25, 26, 27, 28, 29, 30, 31, 32,
		},
	})
	body := []byte(`{"challengeId":"challenge_test","secondFactor":"123456"}`)
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/auth/login/complete", bytes.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Token == "" {
		t.Fatal("login response did not contain a JWT")
	}
	if cookies := response.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("authentication cookies were set: %v", cookies)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q", got)
	}
}

func TestLoginAuthenticationAuditUsesOnlyPrehashedFingerprint(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	identityService := &fakeIdentityService{
		session: identity.Session{
			RawToken:  "opaque-session-token",
			ExpiresAt: now.Add(identity.SessionAbsoluteLifetime),
		},
		principal: identity.SessionPrincipal{
			UserID: "usr_test", SessionID: "ses_test", IssuedAt: now,
		},
	}
	recorder := &recordingAuthAudit{}
	handler := newTestHandler(Dependencies{
		Identity: identityService, AuthAudit: recorder,
		Clock: &fixedClock{now: now}, MasterKey: [32]byte{1},
	})
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/auth/login/complete",
		strings.NewReader(`{"challengeId":"challenge_test","secondFactor":"123456"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "opswarden-test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(recorder.events) != 1 {
		t.Fatalf("audit events=%d", len(recorder.events))
	}
	event := recorder.events[0]
	if event.Actor.Fingerprint == "" ||
		event.Actor.Fingerprint == identityService.session.RawToken ||
		strings.Contains(event.Actor.Fingerprint, identityService.session.RawToken) {
		t.Fatalf("unsafe fingerprint=%q", event.Actor.Fingerprint)
	}
	if event.RequestID == "" || event.SourceIP == "" ||
		event.UserAgent != "opswarden-test" {
		t.Fatalf("missing request metadata: %+v", event)
	}
}

func TestFailedAuthenticationAuditNeverContainsSubmittedCredentials(t *testing.T) {
	emailFixture := "sensitive-user@example.test"
	passwordFixture := "fixture-password-must-not-appear"
	recorder := &recordingAuthAudit{}
	handler := newTestHandler(Dependencies{
		Identity: &fakeIdentityService{
			beginError: identity.ErrInvalidCredentials,
		},
		AuthAudit: recorder, Clock: &fixedClock{now: time.Now().UTC()},
		MasterKey: [32]byte{1},
	})
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/auth/login/begin",
		strings.NewReader(
			`{"email":"`+emailFixture+`","password":"`+passwordFixture+`"}`,
		),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(recorder.events) != 1 ||
		recorder.events[0].Actor.Type != audit.ActorAnonymous {
		t.Fatalf("events=%+v", recorder.events)
	}
	encoded, err := json.Marshal(recorder.events)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(emailFixture)) ||
		bytes.Contains(encoded, []byte(passwordFixture)) {
		t.Fatalf("authentication fixture leaked into audit: %s", encoded)
	}
}

func TestProtectedAuthRouteFailureHasOneRouteSpecificAudit(t *testing.T) {
	recorder := &recordingAuthAudit{}
	handler := newTestHandler(Dependencies{
		Identity: &fakeIdentityService{}, AuthAudit: recorder,
		Clock: &fixedClock{now: time.Now().UTC()}, MasterKey: [32]byte{1},
	})
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/auth/logout", nil,
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(recorder.events) != 1 ||
		recorder.events[0].Action != "auth.logout" ||
		recorder.events[0].Success {
		t.Fatalf("failure audits=%+v", recorder.events)
	}
}

func TestRequiredAuthenticationFailureAuditFailsClosed(t *testing.T) {
	recorder := &recordingAuthAudit{failAction: "auth.jwt"}
	handler := newTestHandler(Dependencies{
		Identity: &fakeIdentityService{}, AuthAudit: recorder,
		Clock: &fixedClock{now: time.Now().UTC()}, MasterKey: [32]byte{1},
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), `"code":"STORAGE_UNAVAILABLE"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAnonymousAuthenticationFloodHasBoundedDurableAudit(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "auth-gate.db")
	db, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	auditRepository, err := audit.NewRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	auditService, err := audit.NewService(auditRepository)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	identityService := &fakeIdentityService{
		session: identity.Session{
			RawToken: "opaque-session-token", ExpiresAt: now.Add(time.Hour),
		},
		principal: identity.SessionPrincipal{
			UserID: "usr_test", SessionID: "ses_test", IssuedAt: now,
		},
	}
	if _, err := db.Writer.Exec(`
		INSERT INTO users
			(id, email, normalized_email, password_hash, system_role)
		VALUES ('usr_test', 'user@example.test', 'user@example.test', X'01', 'member')
	`); err != nil {
		t.Fatal(err)
	}
	clock := &fixedClock{now: now}
	handler := newTestHandler(Dependencies{
		Identity: identityService, Spaces: fakeSpaceService{},
		AuthAudit: auditService, Clock: clock,
		MasterKey: [32]byte{1},
	})
	const tokenFixture = "invalid-jwt-fixture-must-not-persist"
	var limited int
	for range 100 {
		request := httptest.NewRequest(
			http.MethodGet, "/api/v1/me?leak-query=true", nil,
		)
		request.RemoteAddr = "198.51.100.10:4242"
		request.Header.Set("Authorization", "Bearer "+tokenFixture)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("anonymous authentication flood was never rate limited")
	}
	var rows int
	if err := db.Reader.QueryRow(`
		SELECT count(*) FROM audit_events
	`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows > 8 {
		t.Fatalf("audit rows grew with request count: %d", rows)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	request.RemoteAddr = "198.51.100.11:4242"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("different-IP status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := db.Writer.Exec(`CREATE TABLE auth_gate_probe (id INTEGER)`); err != nil {
		t.Fatalf("audit flood made writer unavailable: %v", err)
	}
	jwt, err := handler.(*Router).jwt.sign(
		identityService.principal.UserID, identityService.session,
	)
	if err != nil {
		t.Fatal(err)
	}
	success := serveAuthorized(
		handler, jwt, http.MethodGet, "/api/v1/me", nil,
	)
	if success.Code != http.StatusOK {
		t.Fatalf("valid JWT blocked by failure quota: %d %s", success.Code, success.Body.String())
	}
	clock.now = clock.now.Add(anonymousFailureWindow)
	rollover := httptest.NewRequest(
		http.MethodGet, "/api/v1/me?still-not-persisted=true", nil,
	)
	rollover.RemoteAddr = "198.51.100.10:4242"
	rollover.Header.Set("Authorization", "Bearer "+tokenFixture)
	rolloverResponse := httptest.NewRecorder()
	handler.ServeHTTP(rolloverResponse, rollover)
	if rolloverResponse.Code != http.StatusUnauthorized {
		t.Fatalf(
			"rollover status=%d body=%s",
			rolloverResponse.Code, rolloverResponse.Body.String(),
		)
	}
	aggregateEvents, _, err := auditService.List(
		context.Background(), audit.Filter{Action: "auth.failure.aggregate"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(aggregateEvents) != 1 ||
		!strings.Contains(aggregateEvents[0].Reason, "suppressed_count=95") {
		t.Fatalf("aggregate audits=%+v", aggregateEvents)
	}
	if _, err := db.Writer.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []string{
		tokenFixture, "leak-query", "still-not-persisted",
	} {
		if bytes.Contains(raw, []byte(fixture)) {
			t.Fatalf("authentication aggregate leaked %q", fixture)
		}
	}
}

func TestKnownLogoutFailureKeepsUserAuditActor(t *testing.T) {
	handler, token, service := authenticatedTestHandler(
		t, &fakeCredentialService{}, nil,
	)
	recorder := &recordingAuthAudit{}
	router := handler.(*Router)
	router.deps.AuthAudit = recorder
	service.logoutError = errors.New("logout unavailable")
	response := serveAuthorized(
		handler, token, http.MethodPost, "/api/v1/auth/logout", nil,
	)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var logoutEvent *audit.Event
	for index := range recorder.events {
		if recorder.events[index].Action == "auth.logout" {
			logoutEvent = &recorder.events[index]
		}
	}
	if logoutEvent == nil || logoutEvent.Actor.Type != audit.ActorUser ||
		logoutEvent.Actor.ID != service.principal.UserID ||
		logoutEvent.Success {
		t.Fatalf("logout audit=%+v events=%+v", logoutEvent, recorder.events)
	}
}

func TestKnownAuthenticationFailureAuditUnavailableReturns503(t *testing.T) {
	handler, token, service := authenticatedTestHandler(
		t, &fakeCredentialService{}, nil,
	)
	recorder := &recordingAuthAudit{failAction: "auth.logout"}
	handler.(*Router).deps.AuthAudit = recorder
	service.logoutError = errors.New("logout unavailable")
	response := serveAuthorized(
		handler, token, http.MethodPost, "/api/v1/auth/logout", nil,
	)
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), `"code":"STORAGE_UNAVAILABLE"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestStateChangeRequiresAuthorizationHeaderEvenWithCookie(t *testing.T) {
	handler := newTestHandler(Dependencies{
		Identity:  &fakeIdentityService{},
		Clock:     &fixedClock{now: time.Now().UTC()},
		MasterKey: [32]byte{1},
	})
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/spaces", strings.NewReader(`{"name":"x"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: "opswarden_session", Value: "ignored"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "ignored") {
		t.Fatalf("cookie value leaked: %s", response.Body.String())
	}
}

type fakeSpaceService struct{}

func (fakeSpaceService) CreateAudited(
	_ context.Context,
	_ spaces.MutationContext,
	input spaces.CreateInput,
) (spaces.Space, error) {
	return spaces.Space{ID: "spc_created", Name: input.Name, Role: spaces.Owner}, nil
}

func (fakeSpaceService) ListForUser(
	context.Context,
	identity.SessionPrincipal,
) ([]spaces.Space, error) {
	return []spaces.Space{{ID: "spc_test", Name: "Test", Role: spaces.Owner}}, nil
}

func (fakeSpaceService) ListMembers(
	context.Context,
	identity.SessionPrincipal,
	string,
) ([]spaces.Member, error) {
	return []spaces.Member{{
		UserID: "usr_test", Email: "owner@example.test",
		Role: spaces.Owner, Version: 1,
	}}, nil
}

func (fakeSpaceService) AddMemberAudited(
	_ context.Context,
	_ spaces.MutationContext,
	_ string,
	userID string,
	role spaces.Role,
) (spaces.Member, error) {
	return spaces.Member{UserID: userID, Role: role, Version: 1}, nil
}

func (fakeSpaceService) ChangeRoleAudited(
	_ context.Context,
	_ spaces.MutationContext,
	_, userID string,
	role spaces.Role,
	expectedVersion uint64,
) (spaces.Member, error) {
	return spaces.Member{
		UserID: userID, Role: role, Version: expectedVersion + 1,
	}, nil
}

func (fakeSpaceService) RemoveMemberAudited(
	context.Context,
	spaces.MutationContext,
	string,
	string,
	uint64,
) error {
	return nil
}

func (fakeSpaceService) ResolveAuthorizationPrincipal(
	_ context.Context,
	session identity.SessionPrincipal,
	spaceID string,
) (authorization.HumanPrincipal, error) {
	return authorization.HumanPrincipal{
		Session: session, SystemRole: identity.SystemRoleMember,
		SpaceRoles: map[string]authorization.Role{spaceID: authorization.RoleOwner},
	}, nil
}

type fakeCredentialService struct {
	fixture       string
	actualSpaceID string
	createCalls   int
}

func (service *fakeCredentialService) List(
	context.Context,
	credentials.Principal,
	credentials.ListFilter,
) ([]credentials.Metadata, string, error) {
	return []credentials.Metadata{{
		ID: "cred_test", SpaceID: "spc_test", DisplayName: "Database",
		Type: credentials.TypeLogin, Version: 1,
	}}, "", nil
}

func (service *fakeCredentialService) Get(
	context.Context,
	credentials.Principal,
	string,
) (credentials.Decrypted, error) {
	return credentials.Decrypted{
		Metadata: credentials.Metadata{
			ID: "cred_other", SpaceID: service.actualSpaceID,
			DisplayName: "Other", Type: credentials.TypeLogin, Version: 1,
		},
		Payload: json.RawMessage(`{"password":"` + service.fixture + `"}`),
	}, nil
}

func (service *fakeCredentialService) Create(
	_ context.Context,
	_ credentials.Principal,
	_ credentials.CreateInput,
	_ credentials.WriteContext,
) (credentials.MutationResult, error) {
	service.createCalls++
	return credentials.MutationResult{ID: "cred_new", Version: 1, Status: 201}, nil
}

func (*fakeCredentialService) Update(
	context.Context,
	credentials.Principal,
	credentials.UpdateInput,
	credentials.WriteContext,
) (credentials.MutationResult, error) {
	return credentials.MutationResult{}, nil
}

func (*fakeCredentialService) Delete(
	context.Context,
	credentials.Principal,
	string,
	uint64,
	credentials.WriteContext,
) error {
	return nil
}

func (*fakeCredentialService) Restore(
	context.Context,
	credentials.Principal,
	string,
	uint64,
	credentials.WriteContext,
) (credentials.Metadata, error) {
	return credentials.Metadata{}, nil
}

type fakeAgentService struct{}

func (fakeAgentService) Authenticate(
	context.Context,
	string,
) (agents.AuthenticatedPrincipal, error) {
	return agents.AuthenticatedPrincipal{
		AgentID: "agt_test", TokenID: "tok_test", TokenPrefix: "owat_abcdefgh",
		Grants: []agents.Grant{{
			SpaceID: "spc_test",
			Scopes: []authorization.Scope{
				authorization.ScopeCredentialCreate,
				authorization.ScopeCredentialList,
			},
		}},
	}, nil
}

func (fakeAgentService) Create(
	context.Context,
	agents.MutationContext,
	agents.CreateInput,
) (agents.Agent, error) {
	return agents.Agent{}, nil
}

func (fakeAgentService) IssueToken(
	context.Context,
	agents.MutationContext,
	string,
	time.Time,
) (agents.IssuedToken, error) {
	return agents.IssuedToken{}, nil
}

func (fakeAgentService) RevokeToken(
	context.Context,
	agents.MutationContext,
	string,
) error {
	return nil
}

func (fakeAgentService) SetGrant(
	context.Context,
	agents.MutationContext,
	string,
	agents.Grant,
) error {
	return nil
}

func (fakeAgentService) ListUsage(
	context.Context,
	agents.MutationContext,
) ([]agents.Usage, error) {
	return nil, nil
}

type countingAgentService struct {
	fakeAgentService
	authenticateCalls atomic.Int64
}

func (service *countingAgentService) Authenticate(
	ctx context.Context,
	raw string,
) (agents.AuthenticatedPrincipal, error) {
	service.authenticateCalls.Add(1)
	return service.fakeAgentService.Authenticate(ctx, raw)
}

func TestCredentialListOmitsPayload(t *testing.T) {
	fixture := "fixture-password-must-not-appear"
	handler, token, _ := authenticatedTestHandler(
		t, &fakeCredentialService{fixture: fixture, actualSpaceID: "spc_test"}, nil,
	)
	response := serveAuthorized(
		handler, token, http.MethodGet,
		"/api/v1/spaces/spc_test/credentials", nil,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if bytes.Contains(response.Body.Bytes(), []byte("payload")) ||
		bytes.Contains(response.Body.Bytes(), []byte(fixture)) {
		t.Fatalf("unsafe credential list: %s", response.Body.String())
	}
}

func TestSpaceMemberRESTIsBoundToPathSpaceAndVersioned(t *testing.T) {
	handler, token, _ := authenticatedTestHandler(
		t, &fakeCredentialService{}, nil,
	)
	create := serveAuthorized(
		handler, token, http.MethodPost,
		"/api/v1/spaces/spc_test/members",
		strings.NewReader(`{"userId":"member","role":"reader"}`),
	)
	if create.Code != http.StatusCreated ||
		!strings.Contains(create.Body.String(), `"version":1`) {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	change := serveAuthorized(
		handler, token, http.MethodPatch,
		"/api/v1/spaces/spc_test/members/member",
		strings.NewReader(`{"role":"editor","expectedVersion":1}`),
	)
	if change.Code != http.StatusOK ||
		!strings.Contains(change.Body.String(), `"version":2`) {
		t.Fatalf("change status=%d body=%s", change.Code, change.Body.String())
	}
}

func TestSpaceMemberMutationRejectsZeroExpectedVersionAsInvalidRequest(t *testing.T) {
	handler, token, _ := authenticatedTestHandler(
		t, &fakeCredentialService{}, nil,
	)
	tests := []struct {
		method string
		body   string
	}{
		{
			method: http.MethodPatch,
			body:   `{"role":"editor","expectedVersion":0}`,
		},
		{
			method: http.MethodDelete,
			body:   `{"expectedVersion":0}`,
		},
	}
	for _, test := range tests {
		response := serveAuthorized(
			handler, token, test.method,
			"/api/v1/spaces/spc_test/members/member",
			strings.NewReader(test.body),
		)
		if response.Code != http.StatusBadRequest ||
			!strings.Contains(response.Body.String(), `"code":"INVALID_REQUEST"`) {
			t.Fatalf(
				"%s status=%d body=%s",
				test.method, response.Code, response.Body.String(),
			)
		}
	}
}

func TestCredentialPathSpaceMismatchIsConcealed(t *testing.T) {
	fixture := "fixture-password-must-not-appear"
	handler, token, _ := authenticatedTestHandler(
		t, &fakeCredentialService{fixture: fixture, actualSpaceID: "spc_actual"}, nil,
	)
	response := serveAuthorized(
		handler, token, http.MethodGet,
		"/api/v1/spaces/spc_requested/credentials/cred_other", nil,
	)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), fixture) {
		t.Fatalf("credential leaked: %s", response.Body.String())
	}
}

func TestAgentCredentialWriteRequiresIdempotencyHeader(t *testing.T) {
	credentialService := &fakeCredentialService{actualSpaceID: "spc_test"}
	handler := newTestHandler(Dependencies{
		Identity: &fakeIdentityService{}, Spaces: fakeSpaceService{},
		Credentials: credentialService, Agents: fakeAgentService{},
		Clock:     &fixedClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)},
		MasterKey: [32]byte{1},
	})
	body := strings.NewReader(
		`{"displayName":"x","type":"login","tags":{},` +
			`"assetIds":[],"payload":{"url":"https://x","username":"u","password":"p"}}`,
	)
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/spaces/spc_test/credentials", body,
	)
	request.Header.Set("Authorization", "Bearer owat_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if credentialService.createCalls != 0 {
		t.Fatalf("credential create calls=%d", credentialService.createCalls)
	}
}

func TestCredentialLimiterSeparatesAgentAndHumanSubjects(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := agents.NewLimiter(agents.LimiterConfig{
		Capacity: map[agents.Operation]int{
			agents.OperationCredentialList: 1,
		},
		RefillPerSecond: map[agents.Operation]float64{
			agents.OperationCredentialList: 0.000001,
		},
	})
	credentialService := &fakeCredentialService{actualSpaceID: "spc_test"}
	identityService := &fakeIdentityService{
		session: identity.Session{
			RawToken: "opaque-session-token", ExpiresAt: now.Add(time.Hour),
		},
		principal: identity.SessionPrincipal{
			UserID: "usr_test", SessionID: "ses_test", IssuedAt: now,
		},
	}
	handler := newTestHandler(Dependencies{
		Identity: identityService, Spaces: fakeSpaceService{},
		Credentials: credentialService, Agents: fakeAgentService{},
		Limiter: limiter, Clock: &fixedClock{now: now}, MasterKey: [32]byte{1},
	})
	agentToken := "owat_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	first := serveAuthorized(
		handler, agentToken, http.MethodGet,
		"/api/v1/spaces/spc_test/credentials", nil,
	)
	second := serveAuthorized(
		handler, agentToken, http.MethodGet,
		"/api/v1/spaces/spc_test/credentials", nil,
	)
	if first.Code != http.StatusOK || second.Code != http.StatusTooManyRequests {
		t.Fatalf(
			"agent statuses=(%d,%d) bodies=(%s,%s)",
			first.Code, second.Code, first.Body.String(), second.Body.String(),
		)
	}
	jwt, err := handler.(*Router).jwt.sign(
		identityService.principal.UserID, identityService.session,
	)
	if err != nil {
		t.Fatal(err)
	}
	human := serveAuthorized(
		handler, jwt, http.MethodGet,
		"/api/v1/spaces/spc_test/credentials", nil,
	)
	if human.Code != http.StatusOK {
		t.Fatalf("human status=%d body=%s", human.Code, human.Body.String())
	}
}

func TestSuccessfulAgentAuthenticationDoesNotSpendFailureBudget(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := agents.NewLimiter(agents.LimiterConfig{
		Capacity: map[agents.Operation]int{
			agents.OperationAuthFailure:    1,
			agents.OperationCredentialList: 10,
		},
		RefillPerSecond: map[agents.Operation]float64{
			agents.OperationAuthFailure:    0.000001,
			agents.OperationCredentialList: 1,
		},
	})
	handler := newTestHandler(Dependencies{
		Identity: &fakeIdentityService{}, Spaces: fakeSpaceService{},
		Credentials: &fakeCredentialService{}, Agents: fakeAgentService{},
		Limiter: limiter, Clock: &fixedClock{now: now}, MasterKey: [32]byte{1},
	})
	token := "owat_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	for index := range 2 {
		response := serveAuthorized(
			handler, token, http.MethodGet,
			"/api/v1/spaces/spc_test/credentials", nil,
		)
		if response.Code != http.StatusOK {
			t.Fatalf(
				"request %d status=%d body=%s",
				index+1, response.Code, response.Body.String(),
			)
		}
	}
}

func TestProtectedRequestQuotaRunsBeforeHumanSessionAndAuditWrites(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	service := &fakeIdentityService{
		session: identity.Session{
			RawToken: "session-a", ExpiresAt: now.Add(time.Hour),
		},
		principal: identity.SessionPrincipal{
			UserID: "usr_a", SessionID: "ses_a", IssuedAt: now,
		},
	}
	recorder := &recordingAuthAudit{}
	handler := newTestHandler(Dependencies{
		Identity: service, Spaces: fakeSpaceService{}, AuthAudit: recorder,
		Clock: &fixedClock{now: now}, MasterKey: [32]byte{1},
		Limiter: agents.NewLimiter(agents.LimiterConfig{
			Capacity: map[agents.Operation]int{
				agents.OperationRequestSource: 10,
				agents.OperationRequestRead:   2,
			},
			RefillPerSecond: map[agents.Operation]float64{
				agents.OperationRequestSource: 0.000001,
				agents.OperationRequestRead:   0.000001,
			},
		}),
	})
	token, err := handler.(*Router).jwt.sign(
		service.principal.UserID, service.session,
	)
	if err != nil {
		t.Fatal(err)
	}
	for index := range 7 {
		response := serveAuthorized(
			handler, token, http.MethodGet, "/api/v1/me", nil,
		)
		if index < 2 && response.Code != http.StatusOK {
			t.Fatalf("request %d status=%d body=%s", index, response.Code, response.Body.String())
		}
		if index >= 2 && response.Code != http.StatusTooManyRequests {
			t.Fatalf("request %d escaped pre-auth quota: %d", index, response.Code)
		}
	}
	if service.resolveCalls.Load() != 2 {
		t.Fatalf("session persistence calls=%d want 2", service.resolveCalls.Load())
	}
	if events := recorder.eventCount(); events != 2 {
		t.Fatalf("success audit writes=%d want 2", events)
	}
}

func TestProtectedSourceQuotaBoundsRotatingHumanTokens(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	service := &fakeIdentityService{principals: make(map[string]identity.SessionPrincipal)}
	recorder := &recordingAuthAudit{}
	handler := newTestHandler(Dependencies{
		Identity: service, Spaces: fakeSpaceService{}, AuthAudit: recorder,
		Clock: &fixedClock{now: now}, MasterKey: [32]byte{1},
		Limiter: agents.NewLimiter(agents.LimiterConfig{
			Capacity: map[agents.Operation]int{
				agents.OperationRequestSource: 3,
				agents.OperationRequestRead:   10,
			},
			RefillPerSecond: map[agents.Operation]float64{
				agents.OperationRequestSource: 0.000001,
				agents.OperationRequestRead:   0.000001,
			},
		}),
	})
	for index := range 7 {
		raw := fmt.Sprintf("rotating-session-%d", index)
		principal := identity.SessionPrincipal{
			UserID:    fmt.Sprintf("usr_%d", index),
			SessionID: fmt.Sprintf("ses_%d", index), IssuedAt: now,
		}
		service.principals[raw] = principal
		token, err := handler.(*Router).jwt.sign(principal.UserID, identity.Session{
			RawToken: raw, ExpiresAt: now.Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		request.RemoteAddr = "198.51.100.220:4242"
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if index < 3 && response.Code != http.StatusOK {
			t.Fatalf("request %d status=%d", index, response.Code)
		}
		if index >= 3 && response.Code != http.StatusTooManyRequests {
			t.Fatalf("rotating token %d escaped source quota: %d", index, response.Code)
		}
	}
	if service.resolveCalls.Load() != 3 || recorder.eventCount() != 3 {
		t.Fatalf(
			"persistent writes resolve=%d audit=%d",
			service.resolveCalls.Load(), recorder.eventCount(),
		)
	}
}

func TestProtectedAssetQuotaRunsBeforeAgentLastUsedAndIsNamespaced(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	agentService := &countingAgentService{}
	recorder := &recordingAuthAudit{}
	handler := newTestHandler(Dependencies{
		Identity: &fakeIdentityService{}, Spaces: fakeSpaceService{},
		Assets: &fakeAssetService{}, Agents: agentService, AuthAudit: recorder,
		Clock: &fixedClock{now: now}, MasterKey: [32]byte{1},
		Limiter: agents.NewLimiter(agents.LimiterConfig{
			Capacity: map[agents.Operation]int{
				agents.OperationRequestSource: 10,
				agents.OperationRequestRead:   1,
			},
			RefillPerSecond: map[agents.Operation]float64{
				agents.OperationRequestSource: 0.000001,
				agents.OperationRequestRead:   0.000001,
			},
		}),
	})
	agentToken := "owat_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	for index := range 4 {
		response := serveAuthorized(
			handler, agentToken, http.MethodGet,
			"/api/v1/spaces/spc_test/assets", nil,
		)
		if index == 0 && response.Code != http.StatusOK {
			t.Fatalf("first agent request=%d body=%s", response.Code, response.Body.String())
		}
		if index > 0 && response.Code != http.StatusTooManyRequests {
			t.Fatalf("agent request %d escaped quota: %d", index, response.Code)
		}
	}
	if calls := agentService.authenticateCalls.Load(); calls != 1 {
		t.Fatalf("Agent last-used writes=%d want 1", calls)
	}
	if recorder.eventCount() != 1 {
		t.Fatalf("Agent success audit writes=%d want 1", recorder.eventCount())
	}
}

func TestInvalidJWTRotationUsesOnlyBoundedSourceAdmission(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := agents.NewLimiter(agents.LimiterConfig{
		Capacity: map[agents.Operation]int{
			agents.OperationRequestSource: 30_000,
			agents.OperationRequestRead:   30_000,
		},
		RefillPerSecond: map[agents.Operation]float64{
			agents.OperationRequestSource: 0.000001,
			agents.OperationRequestRead:   0.000001,
		},
		MaxSubjects: 128,
	})
	service := &fakeIdentityService{}
	handler := newTestHandler(Dependencies{
		Identity: service, Spaces: fakeSpaceService{}, Limiter: limiter,
		Clock: &fixedClock{now: now}, MasterKey: [32]byte{1},
	})
	started := time.Now()
	for index := range 20_000 {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		request.RemoteAddr = "198.51.100.230:4242"
		request.Header.Set(
			"Authorization", fmt.Sprintf("Bearer invalid-jwt-%d", index),
		)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized &&
			response.Code != http.StatusTooManyRequests {
			t.Fatalf("request %d status=%d", index, response.Code)
		}
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("invalid JWT rotation took %s", elapsed)
	}
	if count := limiter.SubjectCountFor(agents.OperationRequestSource); count != 1 {
		t.Fatalf("source subjects=%d want 1", count)
	}
	if count := limiter.SubjectCountFor(agents.OperationRequestRead); count != 0 {
		t.Fatalf("invalid JWTs created %d strict subjects", count)
	}
	if work := limiter.WorkUnitsFor(agents.OperationRequestRead); work != 0 {
		t.Fatalf("invalid JWT strict work=%d want 0", work)
	}
	if service.resolveCalls.Load() != 0 {
		t.Fatalf("invalid JWTs reached session persistence %d times", service.resolveCalls.Load())
	}
}

func TestRefreshedJWTsShareStableSessionQuotaAcrossSources(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	clock := &fixedClock{now: now}
	service := &fakeIdentityService{
		principals: map[string]identity.SessionPrincipal{
			"stable-session": {
				UserID: "usr_stable", SessionID: "ses_stable", IssuedAt: now,
			},
			"other-session": {
				UserID: "usr_other", SessionID: "ses_other", IssuedAt: now,
			},
		},
	}
	recorder := &recordingAuthAudit{}
	handler := newTestHandler(Dependencies{
		Identity: service, Spaces: fakeSpaceService{}, AuthAudit: recorder,
		Clock: clock, MasterKey: [32]byte{1},
		Limiter: agents.NewLimiter(agents.LimiterConfig{
			Capacity: map[agents.Operation]int{
				agents.OperationRequestSource: 20,
				agents.OperationRequestWrite:  2,
			},
			RefillPerSecond: map[agents.Operation]float64{
				agents.OperationRequestSource: 0.000001,
				agents.OperationRequestWrite:  0.000001,
			},
		}),
	})
	current, err := handler.(*Router).jwt.sign(
		"usr_stable", identity.Session{
			RawToken: "stable-session", ExpiresAt: now.Add(time.Hour),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(time.Second)
	for index := range 3 {
		request := httptest.NewRequest(
			http.MethodPost, "/api/v1/auth/refresh", nil,
		)
		request.RemoteAddr = fmt.Sprintf("198.51.100.%d:4242", index+240)
		request.Header.Set("Authorization", "Bearer "+current)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if index < 2 {
			if response.Code != http.StatusOK {
				t.Fatalf("refresh %d status=%d body=%s", index, response.Code, response.Body.String())
			}
			var result struct {
				Token string `json:"token"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			current = result.Token
			clock.now = clock.now.Add(time.Second)
		} else if response.Code != http.StatusTooManyRequests {
			t.Fatalf("refreshed JWT reset session quota: %d", response.Code)
		}
	}
	if calls := service.resolveCalls.Load(); calls != 2 {
		t.Fatalf("over-limit refresh reached session persistence: %d", calls)
	}
	if events := recorder.eventCount(); events != 4 {
		t.Fatalf("over-limit refresh changed audit rows: %d", events)
	}

	otherToken, err := handler.(*Router).jwt.sign(
		"usr_other", identity.Session{
			RawToken: "other-session", ExpiresAt: now.Add(time.Hour),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	other := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	other.RemoteAddr = "198.51.100.250:4242"
	other.Header.Set("Authorization", "Bearer "+otherToken)
	otherResponse := httptest.NewRecorder()
	handler.ServeHTTP(otherResponse, other)
	if otherResponse.Code != http.StatusOK {
		t.Fatalf(
			"one session blocked another: %d %s",
			otherResponse.Code, otherResponse.Body.String(),
		)
	}
}

type blockingIdentityService struct {
	*fakeIdentityService
	started chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	calls   int
}

type blockingBootstrapIdentityService struct {
	*fakeIdentityService
	release chan struct{}
	mu      sync.Mutex
	calls   int
}

func (service *blockingBootstrapIdentityService) CreateInitialOwner(
	context.Context,
	identity.CreateOwnerInput,
) (identity.CreateOwnerResult, error) {
	service.mu.Lock()
	service.calls++
	service.mu.Unlock()
	<-service.release
	return identity.CreateOwnerResult{}, identity.ErrInvalidOwnerInput
}

type blockingEOFReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (reader *blockingEOFReader) Read([]byte) (int, error) {
	reader.once.Do(func() { close(reader.started) })
	<-reader.release
	return 0, io.EOF
}

func (service *blockingIdentityService) BeginLogin(
	context.Context,
	string,
	string,
) (identity.LoginChallenge, error) {
	service.mu.Lock()
	service.calls++
	service.mu.Unlock()
	service.once.Do(func() { close(service.started) })
	<-service.release
	return identity.LoginChallenge{}, identity.ErrInvalidCredentials
}

func TestLoginFailureReservationBlocksConcurrentAuthenticationBurst(t *testing.T) {
	service := &blockingIdentityService{
		fakeIdentityService: &fakeIdentityService{},
		started:             make(chan struct{}),
		release:             make(chan struct{}),
	}
	handler := loginLimitTestHandler(t, service, nil)
	firstResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstResult <- postLoginBegin(
			handler, `{"email":"u@example.com","password":"bad"}`,
			"198.51.100.10:4242", "",
		)
	}()
	<-service.started

	const attempts = 32
	results := make(chan int, attempts)
	var workers sync.WaitGroup
	for range attempts {
		workers.Add(1)
		go func() {
			defer workers.Done()
			response := postLoginBegin(
				handler, `{"email":"u@example.com","password":"bad"}`,
				"198.51.100.10:4242", "",
			)
			results <- response.Code
		}()
	}
	workers.Wait()
	close(results)
	for status := range results {
		if status != http.StatusTooManyRequests {
			t.Fatalf("concurrent status=%d", status)
		}
	}
	service.mu.Lock()
	calls := service.calls
	service.mu.Unlock()
	if calls != 1 {
		t.Fatalf("concurrent authentication executions=%d", calls)
	}
	close(service.release)
	if response := <-firstResult; response.Code != http.StatusUnauthorized {
		t.Fatalf("first status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSlowLoginBodyDoesNotReserveAuthenticationFailureCapacity(t *testing.T) {
	handler := loginLimitTestHandler(t, &fakeIdentityService{}, nil)
	reader := &blockingEOFReader{
		started: make(chan struct{}), release: make(chan struct{}),
	}
	firstResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		request := httptest.NewRequest(
			http.MethodPost, "/api/v1/auth/login/begin", reader,
		)
		request.RemoteAddr = "198.51.100.10:4242"
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		firstResult <- response
	}()
	<-reader.started
	second := postLoginBegin(
		handler, `{"email":"other@example.test","password":"good"}`,
		"198.51.100.10:4242", "",
	)
	if second.Code != http.StatusOK {
		t.Fatalf(
			"slow body reserved auth capacity: status=%d body=%s",
			second.Code, second.Body.String(),
		)
	}
	close(reader.release)
	if first := <-firstResult; first.Code != http.StatusBadRequest {
		t.Fatalf("slow request status=%d body=%s", first.Code, first.Body.String())
	}
}

func TestLoginFailureQuotaSeparatesAccountsBehindOneNAT(t *testing.T) {
	handler := loginLimitTestHandler(
		t, &fakeIdentityService{beginError: identity.ErrInvalidCredentials}, nil,
	)
	first := postLoginBegin(
		handler, `{"email":"first@example.test","password":"bad"}`,
		"198.51.100.10:4242", "",
	)
	second := postLoginBegin(
		handler, `{"email":"second@example.test","password":"bad"}`,
		"198.51.100.10:4242", "",
	)
	if first.Code != http.StatusUnauthorized ||
		second.Code != http.StatusUnauthorized {
		t.Fatalf(
			"NAT account statuses=(%d,%d) bodies=(%s,%s)",
			first.Code, second.Code, first.Body.String(), second.Body.String(),
		)
	}
}

func TestLoginSourceQuotaBoundsRotatingAccounts(t *testing.T) {
	service := &fakeIdentityService{beginError: identity.ErrInvalidCredentials}
	handler := newTestHandler(Dependencies{
		Identity: service, AuthAudit: &recordingAuthAudit{},
		Clock:     &fixedClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)},
		MasterKey: [32]byte{1},
		Limiter: agents.NewLimiter(agents.LimiterConfig{
			Capacity: map[agents.Operation]int{
				agents.OperationLoginSource: 3,
				agents.OperationAuthFailure: 10,
			},
			RefillPerSecond: map[agents.Operation]float64{
				agents.OperationLoginSource: 0.000001,
				agents.OperationAuthFailure: 0.000001,
			},
		}),
	})
	for index := range 8 {
		response := postLoginBegin(
			handler,
			fmt.Sprintf(
				`{"email":"rotating-%d@example.com","password":"bad"}`,
				index,
			),
			"198.51.100.40:4242", "",
		)
		if index < 3 && response.Code != http.StatusUnauthorized {
			t.Fatalf("request %d status=%d", index, response.Code)
		}
		if index >= 3 && response.Code != http.StatusTooManyRequests {
			t.Fatalf("request %d escaped source quota: %d", index, response.Code)
		}
	}
	if calls := service.beginCalls.Load(); calls != 3 {
		t.Fatalf("password work calls=%d want source capacity 3", calls)
	}
}

func TestLoginAccountQuotaSurvivesSourceRotation(t *testing.T) {
	service := &fakeIdentityService{beginError: identity.ErrInvalidCredentials}
	handler := newTestHandler(Dependencies{
		Identity: service, AuthAudit: &recordingAuthAudit{},
		Clock:     &fixedClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)},
		MasterKey: [32]byte{1},
		Limiter: agents.NewLimiter(agents.LimiterConfig{
			Capacity: map[agents.Operation]int{
				agents.OperationLoginSource: 10,
				agents.OperationAuthFailure: 2,
			},
			RefillPerSecond: map[agents.Operation]float64{
				agents.OperationLoginSource: 0.000001,
				agents.OperationAuthFailure: 0.000001,
			},
		}),
	})
	for index := range 5 {
		response := postLoginBegin(
			handler,
			`{"email":"target@example.com","password":"bad"}`,
			fmt.Sprintf("198.51.100.%d:4242", index+50), "",
		)
		if index < 2 && response.Code != http.StatusUnauthorized {
			t.Fatalf("request %d status=%d", index, response.Code)
		}
		if index >= 2 && response.Code != http.StatusTooManyRequests {
			t.Fatalf("request %d escaped account quota: %d", index, response.Code)
		}
	}
	if calls := service.beginCalls.Load(); calls != 2 {
		t.Fatalf("password work calls=%d want account capacity 2", calls)
	}
}

func TestLoginDualQuotaReservationIsAtomicUnderConcurrency(t *testing.T) {
	service := &fakeIdentityService{beginError: identity.ErrInvalidCredentials}
	handler := newTestHandler(Dependencies{
		Identity: service, AuthAudit: &recordingAuthAudit{},
		Clock:     &fixedClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)},
		MasterKey: [32]byte{1},
		Limiter: agents.NewLimiter(agents.LimiterConfig{
			Capacity: map[agents.Operation]int{
				agents.OperationLoginSource: 3,
				agents.OperationAuthFailure: 20,
			},
			RefillPerSecond: map[agents.Operation]float64{
				agents.OperationLoginSource: 0.000001,
				agents.OperationAuthFailure: 0.000001,
			},
		}),
	})
	var workers sync.WaitGroup
	for index := range 32 {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			postLoginBegin(
				handler,
				fmt.Sprintf(
					`{"email":"concurrent-%d@example.com","password":"bad"}`,
					index,
				),
				"198.51.100.90:4242", "",
			)
		}(index)
	}
	workers.Wait()
	if calls := service.beginCalls.Load(); calls > 3 {
		t.Fatalf("concurrent password work calls=%d want <=3", calls)
	}
}

func TestPasswordKDFConcurrencyIsGloballyBounded(t *testing.T) {
	service := &blockingIdentityService{
		fakeIdentityService: &fakeIdentityService{},
		started:             make(chan struct{}),
		release:             make(chan struct{}),
	}
	handler := loginLimitTestHandler(t, service, nil)
	const attempts = 12
	results := make(chan int, attempts)
	var workers sync.WaitGroup
	for index := range attempts {
		workers.Add(1)
		go func() {
			defer workers.Done()
			request := httptest.NewRequest(
				http.MethodPost, "/api/v1/auth/login/begin",
				strings.NewReader(
					fmt.Sprintf(
						`{"email":"user-%d@example.test","password":"bad"}`,
						index,
					),
				),
			)
			request.RemoteAddr = fmt.Sprintf("198.51.100.%d:4242", index+1)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			results <- response.Code
		}()
	}
	time.Sleep(250 * time.Millisecond)
	service.mu.Lock()
	calls := service.calls
	service.mu.Unlock()
	close(service.release)
	workers.Wait()
	close(results)
	if calls > 4 {
		t.Fatalf("concurrent password KDF calls=%d, want <=4", calls)
	}
	var limited int
	for status := range results {
		if status == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("password KDF saturation never returned 429")
	}
}

func TestBootstrapKDFConcurrencyAndIPQuotaAreIndependent(t *testing.T) {
	service := &blockingBootstrapIdentityService{
		fakeIdentityService: &fakeIdentityService{},
		release:             make(chan struct{}),
	}
	handler := loginLimitTestHandler(t, service, nil)
	const attempts = 12
	results := make(chan int, attempts)
	var workers sync.WaitGroup
	for index := range attempts {
		workers.Add(1)
		go func() {
			defer workers.Done()
			request := httptest.NewRequest(
				http.MethodPost, "/api/v1/bootstrap/initial-owner",
				strings.NewReader(
					fmt.Sprintf(
						`{"email":"owner-%d@example.test",`+
							`"password":"strong-password",`+
							`"totpSeed":"JBSWY3DPEHPK3PXP"}`,
						index,
					),
				),
			)
			request.RemoteAddr = fmt.Sprintf("127.0.0.%d:4242", index+1)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			results <- response.Code
		}()
	}
	time.Sleep(250 * time.Millisecond)
	service.mu.Lock()
	calls := service.calls
	service.mu.Unlock()
	close(service.release)
	workers.Wait()
	close(results)
	if calls > 4 {
		t.Fatalf("concurrent bootstrap KDF calls=%d, want <=4", calls)
	}
	var limited int
	for status := range results {
		if status == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("bootstrap KDF saturation never returned 429")
	}

	failing := &fakeIdentityService{ownerError: identity.ErrInvalidOwnerInput}
	quotaHandler := loginLimitTestHandler(t, failing, nil)
	for index := range 3 {
		response := postBootstrap(
			quotaHandler, "127.0.0.20:4242", index,
		)
		want := http.StatusBadRequest
		if index == 2 {
			want = http.StatusTooManyRequests
		}
		if response.Code != want {
			t.Fatalf(
				"same-IP attempt %d status=%d body=%s",
				index+1, response.Code, response.Body.String(),
			)
		}
	}
	otherIP := postBootstrap(quotaHandler, "127.0.0.21:4242", 4)
	if otherIP.Code != http.StatusBadRequest {
		t.Fatalf(
			"different-IP status=%d body=%s",
			otherIP.Code, otherIP.Body.String(),
		)
	}
}

func TestSuccessfulAndMalformedLoginRequestsDoNotSpendFailureBudget(t *testing.T) {
	handler := loginLimitTestHandler(t, &fakeIdentityService{}, nil)
	for _, body := range []string{
		`{"email":"u@example.com","password":"good"}`,
		`{"email":"u@example.com","password":"good"}`,
	} {
		response := postLoginBegin(handler, body, "198.51.100.10:4242", "")
		if response.Code != http.StatusOK {
			t.Fatalf("successful login status=%d body=%s", response.Code, response.Body.String())
		}
	}
	malformed := postLoginBegin(handler, `{`, "198.51.100.10:4242", "")
	if malformed.Code != http.StatusBadRequest {
		t.Fatalf("malformed status=%d body=%s", malformed.Code, malformed.Body.String())
	}
	response := postLoginBegin(
		handler, `{"email":"u@example.com","password":"good"}`,
		"198.51.100.10:4242", "",
	)
	if response.Code != http.StatusOK {
		t.Fatalf("post-malformed status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestTrustedProxySeparatesForwardedClientsButUntrustedSpoofDoesNot(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	handler := loginLimitTestHandler(
		t, &fakeIdentityService{beginError: identity.ErrInvalidCredentials}, trusted,
	)
	for index, forwarded := range []string{"198.51.100.10", "198.51.100.11"} {
		response := postLoginBegin(
			handler,
			fmt.Sprintf(
				`{"email":"u%d@example.com","password":"bad"}`, index,
			),
			"10.0.0.5:443", forwarded,
		)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("trusted forwarded=%s status=%d body=%s", forwarded, response.Code, response.Body.String())
		}
	}

	untrusted := loginLimitTestHandler(
		t, &fakeIdentityService{beginError: identity.ErrInvalidCredentials}, trusted,
	)
	first := postLoginBegin(
		untrusted, `{"email":"u@example.com","password":"bad"}`,
		"203.0.113.9:443", "198.51.100.20",
	)
	second := postLoginBegin(
		untrusted, `{"email":"u@example.com","password":"bad"}`,
		"203.0.113.9:443", "198.51.100.21",
	)
	if first.Code != http.StatusUnauthorized || second.Code != http.StatusTooManyRequests {
		t.Fatalf("untrusted spoof statuses=(%d,%d)", first.Code, second.Code)
	}
}

func loginLimitTestHandler(
	t *testing.T,
	identityService IdentityService,
	trusted []netip.Prefix,
) http.Handler {
	t.Helper()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	return newTestHandler(Dependencies{
		Identity: identityService, Clock: &fixedClock{now: now},
		MasterKey: [32]byte{1}, TrustedProxyCIDRs: trusted,
		Limiter: agents.NewLimiter(agents.LimiterConfig{
			Capacity: map[agents.Operation]int{agents.OperationAuthFailure: 1},
			RefillPerSecond: map[agents.Operation]float64{
				agents.OperationAuthFailure: 0.000001,
			},
		}),
	})
}

func postLoginBegin(
	handler http.Handler,
	body string,
	remoteAddr string,
	forwardedFor string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/auth/login/begin", strings.NewReader(body),
	)
	request.RemoteAddr = remoteAddr
	request.Header.Set("Content-Type", "application/json")
	if forwardedFor != "" {
		request.Header.Set("X-Forwarded-For", forwardedFor)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func postBootstrap(
	handler http.Handler,
	remoteAddr string,
	index int,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/bootstrap/initial-owner",
		strings.NewReader(
			fmt.Sprintf(
				`{"email":"owner-%d@example.test",`+
					`"password":"strong-password",`+
					`"totpSeed":"JBSWY3DPEHPK3PXP"}`,
				index,
			),
		),
	)
	request.RemoteAddr = remoteAddr
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestDuplicateCredentialLabelKeyIsRejectedBeforeMapDecode(t *testing.T) {
	credentialService := &fakeCredentialService{actualSpaceID: "spc_test"}
	handler, token, _ := authenticatedTestHandler(t, credentialService, nil)
	body := strings.NewReader(
		`{"displayName":"x","type":"login","tags":{"env":"dev","env":"prod"},` +
			`"assetIds":[],"payload":{"url":"https://x","username":"u","password":"p"}}`,
	)
	response := serveAuthorized(
		handler, token, http.MethodPost,
		"/api/v1/spaces/spc_test/credentials", body,
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if credentialService.createCalls != 0 {
		t.Fatalf("credential create calls=%d", credentialService.createCalls)
	}
}

func TestMalformedQueryEncodingIsRejected(t *testing.T) {
	handler, token, _ := authenticatedTestHandler(
		t, &fakeCredentialService{}, nil,
	)
	response := serveAuthorized(
		handler, token, http.MethodGet,
		"/api/v1/spaces/spc_test/credentials?type=%ZZ", nil,
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestJSONFieldsAreCaseSensitiveAndCanonical(t *testing.T) {
	handler := newTestHandler(Dependencies{
		Identity:  &fakeIdentityService{},
		Clock:     &fixedClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)},
		MasterKey: [32]byte{1},
	})
	response := postLoginBegin(
		handler, `{"Email":"u@example.com","Password":"p"}`,
		"198.51.100.10:4242", "",
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestNoQueryRoutesRejectEveryQuery(t *testing.T) {
	handler := newTestHandler(Dependencies{
		Identity:  &fakeIdentityService{},
		Clock:     &fixedClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)},
		MasterKey: [32]byte{1},
	})
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/auth/login/begin?debug=true",
		strings.NewReader(`{"email":"u@example.com","password":"p"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRevokedServerSessionInvalidatesUnexpiredJWT(t *testing.T) {
	handler, token, identityService := authenticatedTestHandler(
		t, &fakeCredentialService{}, nil,
	)
	identityService.resolveError = identity.ErrSessionRevoked
	response := serveAuthorized(
		handler, token, http.MethodGet, "/api/v1/spaces", nil,
	)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if identityService.resolveCalls.Load() == 0 {
		t.Fatal("server-side session was not resolved")
	}
}

func TestSpaceResponsesUseStableCamelCaseFields(t *testing.T) {
	handler, token, _ := authenticatedTestHandler(
		t, &fakeCredentialService{}, nil,
	)
	response := serveAuthorized(
		handler, token, http.MethodGet, "/api/v1/spaces", nil,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"id":"spc_test"`) ||
		strings.Contains(body, `"ID"`) {
		t.Fatalf("unstable JSON fields: %s", body)
	}
}

func TestMeReturnsFreshResolvedIdentity(t *testing.T) {
	handler, token, _ := authenticatedTestHandler(
		t, &fakeCredentialService{}, nil,
	)
	response := serveAuthorized(
		handler, token, http.MethodGet, "/api/v1/me", nil,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"userId":"usr_test"`) ||
		!strings.Contains(body, `"systemRole":"member"`) ||
		strings.Contains(body, "opaque-session-token") {
		t.Fatalf("unsafe or incomplete me response: %s", body)
	}
}

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *synchronizedBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(data)
}

func (buffer *synchronizedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

func TestErrorsAndLogsRedactRequestBody(t *testing.T) {
	fixture := "fixture-password-must-not-appear"
	logs := &synchronizedBuffer{}
	handler, token, _ := authenticatedTestHandler(
		t, &fakeCredentialService{}, slog.New(slog.NewJSONHandler(logs, nil)),
	)
	body := strings.NewReader(
		`{"displayName":"` + fixture + `","displayName":"duplicate"}`,
	)
	response := serveAuthorized(
		handler, token, http.MethodPost,
		"/api/v1/spaces/spc_test/credentials", body,
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(logs.String(), fixture) ||
		strings.Contains(response.Body.String(), fixture) {
		t.Fatalf("request body leaked: logs=%s body=%s", logs.String(), response.Body.String())
	}
}

func authenticatedTestHandler(
	t *testing.T,
	credentialService CredentialService,
	logger *slog.Logger,
) (http.Handler, string, *fakeIdentityService) {
	t.Helper()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	identityService := &fakeIdentityService{
		session: identity.Session{
			RawToken:  "opaque-session-token",
			ExpiresAt: now.Add(identity.SessionAbsoluteLifetime),
		},
		principal: identity.SessionPrincipal{
			UserID: "usr_test", SessionID: "ses_test", IssuedAt: now,
		},
	}
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}
	handler := newTestHandler(Dependencies{
		Identity: identityService, Spaces: fakeSpaceService{},
		Credentials: credentialService, Clock: &fixedClock{now: now},
		Logger: logger, MasterKey: key,
	})
	token, err := handler.(*Router).jwt.sign(
		identityService.principal.UserID, identityService.session,
	)
	if err != nil {
		t.Fatal(err)
	}
	return handler, token, identityService
}

func serveAuthorized(
	handler http.Handler,
	token string,
	method string,
	target string,
	body io.Reader,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, body)
	request.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

var _ AssetService = (*fakeAssetService)(nil)

type fakeAssetService struct{}

func (*fakeAssetService) List(context.Context, assets.Principal, assets.ListFilter) ([]assets.Asset, string, error) {
	return nil, "", nil
}
func (*fakeAssetService) Get(context.Context, assets.Principal, string) (assets.Asset, error) {
	return assets.Asset{}, nil
}
func (*fakeAssetService) Create(context.Context, assets.Principal, assets.CreateInput) (assets.Asset, error) {
	return assets.Asset{}, nil
}
func (*fakeAssetService) Update(context.Context, assets.Principal, assets.UpdateInput) (assets.Asset, error) {
	return assets.Asset{}, nil
}
func (*fakeAssetService) Delete(context.Context, assets.Principal, string, uint64) error {
	return nil
}
func (*fakeAssetService) ListCredentialMetadata(context.Context, assets.Principal, string, assets.CredentialListPage) ([]credentials.Metadata, string, error) {
	return nil, "", nil
}
