package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"opswarden/internal/agents"
	"opswarden/internal/assets"
	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/credentials"
	"opswarden/internal/identity"
	"opswarden/internal/spaces"
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
	handler := New(Dependencies{
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
	session      identity.Session
	principal    identity.SessionPrincipal
	resolveError error
	resolveCalls int
}

type recordingAuthAudit struct {
	events []audit.Event
}

func (recorder *recordingAuthAudit) RecordReadBeforeReturn(
	_ context.Context,
	event audit.Event,
) error {
	recorder.events = append(recorder.events, event)
	return nil
}

func (service *fakeIdentityService) BeginLogin(
	context.Context,
	string,
	string,
) (identity.LoginChallenge, error) {
	return identity.LoginChallenge{
		ID: "challenge_test", ExpiresAt: time.Now().Add(time.Minute),
	}, nil
}

func (service *fakeIdentityService) CompleteLogin(
	context.Context,
	string,
	string,
) (identity.Session, error) {
	return service.session, nil
}

func (service *fakeIdentityService) ResolveSession(
	_ context.Context,
	token string,
) (identity.SessionPrincipal, error) {
	service.resolveCalls++
	if token != service.session.RawToken {
		return identity.SessionPrincipal{}, identity.ErrInvalidSession
	}
	if service.resolveError != nil {
		return identity.SessionPrincipal{}, service.resolveError
	}
	return service.principal, nil
}

func (service *fakeIdentityService) Logout(context.Context, string) error {
	return nil
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
	handler := New(Dependencies{
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
	handler := New(Dependencies{
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

func TestStateChangeRequiresAuthorizationHeaderEvenWithCookie(t *testing.T) {
	handler := New(Dependencies{
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
	handler := New(Dependencies{
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
	handler := New(Dependencies{
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
	handler := New(Dependencies{
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
	if identityService.resolveCalls == 0 {
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
	handler := New(Dependencies{
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
