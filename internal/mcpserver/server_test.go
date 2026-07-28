package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"opswarden/internal/agents"
	"opswarden/internal/audit"
	"opswarden/internal/credentials"
)

func TestToolsExposeExactApprovedNames(t *testing.T) {
	got := ToolNames()
	want := []string{
		"asset_get",
		"asset_list",
		"credential_create",
		"credential_delete",
		"credential_get",
		"credential_list",
		"credential_update",
		"totp_generate",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestNewRejectsPartialDomainDependencies(t *testing.T) {
	base := Dependencies{
		Agents: &fakeAuthenticator{}, AuthAudit: &recordingAudit{},
		Clock:   fixedClock{now: time.Now().UTC()},
		Limiter: agents.NewLimiter(agents.LimiterConfig{}),
	}
	if handler, err := New(base); err == nil || handler != nil {
		t.Fatalf("accepted missing domain services: handler=%v err=%v", handler, err)
	}
	base.Credentials = &fakeCredentialService{}
	if handler, err := New(base); err == nil || handler != nil {
		t.Fatalf("accepted missing asset service: handler=%v err=%v", handler, err)
	}
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *mutableClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *mutableClock) set(now time.Time) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = now
}

type fakeAuthenticator struct {
	mu         sync.Mutex
	principal  agents.AuthenticatedPrincipal
	inspectErr error
	authErr    error
	inspects   int
	auths      int
}

func (authenticator *fakeAuthenticator) InspectAuthentication(
	context.Context,
	string,
) (agents.AuthenticatedPrincipal, error) {
	authenticator.mu.Lock()
	defer authenticator.mu.Unlock()
	authenticator.inspects++
	return authenticator.principal, authenticator.inspectErr
}

func (authenticator *fakeAuthenticator) Authenticate(
	context.Context,
	string,
) (agents.AuthenticatedPrincipal, error) {
	authenticator.mu.Lock()
	defer authenticator.mu.Unlock()
	authenticator.auths++
	return authenticator.principal, authenticator.authErr
}

func (authenticator *fakeAuthenticator) revoke() {
	authenticator.mu.Lock()
	defer authenticator.mu.Unlock()
	authenticator.inspectErr = agents.ErrAuthenticationFailed
	authenticator.authErr = agents.ErrAuthenticationFailed
}

func (authenticator *fakeAuthenticator) counts() (int, int) {
	authenticator.mu.Lock()
	defer authenticator.mu.Unlock()
	return authenticator.inspects, authenticator.auths
}

type recordingAudit struct {
	events []audit.Event
}

func (recorder *recordingAudit) RecordReadBeforeReturn(
	_ context.Context,
	event audit.Event,
) error {
	recorder.events = append(recorder.events, event)
	return nil
}

type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (transport bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header.Set("Authorization", "Bearer "+transport.token)
	return transport.base.RoundTrip(clone)
}

func TestOfficialClientDiscoversExactApprovedTools(t *testing.T) {
	now := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
	authenticator := &fakeAuthenticator{principal: agents.AuthenticatedPrincipal{
		AgentID: "agt_test", TokenID: "tok_test", TokenPrefix: "owat_fixture",
	}}
	handler, err := New(Dependencies{
		Agents: authenticator, AuthAudit: &recordingAudit{},
		Credentials: &fakeCredentialService{}, Assets: &fakeAssetService{},
		Clock: fixedClock{now: now}, Limiter: agents.NewLimiter(agents.LimiterConfig{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	httpClient := &http.Client{Transport: bearerTransport{
		base: http.DefaultTransport, token: "owat_fixture-token",
	}}
	client := mcp.NewClient(
		&mcp.Implementation{Name: "opswarden-test", Version: "1.0.0"}, nil,
	)
	session, err := client.Connect(
		context.Background(),
		&mcp.StreamableClientTransport{
			Endpoint: server.URL + "/mcp", HTTPClient: httpClient,
			DisableStandaloneSSE: true,
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	var got []string
	for tool, err := range session.Tools(context.Background(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, tool.Name)
		schema, ok := tool.InputSchema.(map[string]any)
		if !ok || schema["additionalProperties"] != false {
			t.Fatalf("%s input schema is not closed: %#v", tool.Name, tool.InputSchema)
		}
		if tool.OutputSchema == nil {
			t.Fatalf("%s has no explicit output schema", tool.Name)
		}
		assertSchemaFieldDescriptions(t, tool.Name+" input", tool.InputSchema)
		assertSchemaFieldDescriptions(t, tool.Name+" output", tool.OutputSchema)
		if (tool.Name == "credential_get" || tool.Name == "totp_generate") &&
			!strings.Contains(tool.Description, "敏感") {
			t.Fatalf("%s description does not mark sensitive output", tool.Name)
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, ToolNames()) {
		t.Fatalf("got %v want %v", got, ToolNames())
	}
}

func assertSchemaFieldDescriptions(t *testing.T, path string, schema any) {
	t.Helper()
	object, ok := schema.(map[string]any)
	if !ok {
		return
	}
	if properties, ok := object["properties"].(map[string]any); ok {
		for name, rawProperty := range properties {
			property, ok := rawProperty.(map[string]any)
			if !ok {
				t.Fatalf("%s.%s is not an object schema", path, name)
			}
			description, _ := property["description"].(string)
			if strings.TrimSpace(description) == "" {
				t.Fatalf("%s.%s has no description", path, name)
			}
			assertSchemaFieldDescriptions(t, path+"."+name, property)
		}
	}
	if items, ok := object["items"]; ok {
		assertSchemaFieldDescriptions(t, path+"[]", items)
	}
}

func TestServerAdvertisesOnlyToolCapability(t *testing.T) {
	now := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
	handler, err := New(Dependencies{
		Agents: &fakeAuthenticator{principal: agents.AuthenticatedPrincipal{
			AgentID: "agt_test", TokenID: "tok_test", TokenPrefix: "owat_fixture",
		}},
		AuthAudit:   &recordingAudit{},
		Credentials: &fakeCredentialService{}, Assets: &fakeAssetService{},
		Clock:   fixedClock{now: now},
		Limiter: agents.NewLimiter(agents.LimiterConfig{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "http://opswarden.test/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`),
	)
	request.Header.Set("Authorization", "Bearer owat_fixture-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Result struct {
			Capabilities map[string]json.RawMessage `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Result.Capabilities) != 1 ||
		envelope.Result.Capabilities["tools"] == nil {
		t.Fatalf("unexpected capabilities: %s", response.Body.String())
	}
}

func TestTrustedProxySourceIsUsedForAuthenticationAudit(t *testing.T) {
	now := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
	auditRecorder := &recordingAudit{}
	handler, err := New(Dependencies{
		Agents: &fakeAuthenticator{principal: agents.AuthenticatedPrincipal{
			AgentID: "agt_test", TokenID: "tok_test", TokenPrefix: "owat_fixture",
		}},
		AuthAudit:   auditRecorder,
		Credentials: &fakeCredentialService{}, Assets: &fakeAssetService{},
		Clock:   fixedClock{now: now},
		Limiter: agents.NewLimiter(agents.LimiterConfig{}),
		TrustedProxyCIDRs: []netip.Prefix{
			netip.MustParsePrefix("192.0.2.0/24"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "http://opswarden.test/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`),
	)
	request.RemoteAddr = "192.0.2.10:4567"
	request.Header.Set("Authorization", "Bearer owat_fixture-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("X-Forwarded-For", "198.51.100.7")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if len(auditRecorder.events) != 1 ||
		auditRecorder.events[0].SourceIP != "198.51.100.7" {
		t.Fatalf("events=%+v", auditRecorder.events)
	}
}

func TestRevokedAgentTokenFailsOnTheNextMCPRequest(t *testing.T) {
	now := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
	authenticator := &fakeAuthenticator{principal: agents.AuthenticatedPrincipal{
		AgentID: "agt_test", TokenID: "tok_test", TokenPrefix: "owat_fixture",
	}}
	handler, err := New(Dependencies{
		Agents: authenticator, AuthAudit: &recordingAudit{},
		Credentials: &fakeCredentialService{}, Assets: &fakeAssetService{},
		Clock: fixedClock{now: now}, Limiter: agents.NewLimiter(agents.LimiterConfig{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	httpClient := &http.Client{Transport: bearerTransport{
		base: http.DefaultTransport, token: "owat_fixture-token",
	}}
	session, err := mcp.NewClient(
		&mcp.Implementation{Name: "opswarden-test", Version: "1.0.0"}, nil,
	).Connect(
		context.Background(),
		&mcp.StreamableClientTransport{
			Endpoint: server.URL + "/mcp", HTTPClient: httpClient,
			DisableStandaloneSSE: true,
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	authenticator.revoke()
	if _, err := session.CallTool(
		context.Background(),
		&mcp.CallToolParams{
			Name:      "credential_list",
			Arguments: map[string]any{"space_id": "spc_test"},
		},
	); err == nil {
		t.Fatal("revoked token remained usable")
	}
}

func TestStatelessEndpointRejectsClientSessionHeaders(t *testing.T) {
	now := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
	authenticator := &fakeAuthenticator{principal: agents.AuthenticatedPrincipal{
		AgentID: "agt_test", TokenID: "tok_test", TokenPrefix: "owat_fixture",
	}}
	limiter := agents.NewLimiter(agents.LimiterConfig{})
	auditRecorder := &recordingAudit{}
	handler, err := New(Dependencies{
		Agents:      authenticator,
		AuthAudit:   auditRecorder,
		Credentials: &fakeCredentialService{}, Assets: &fakeAssetService{},
		Clock:   fixedClock{now: now},
		Limiter: limiter,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "http://opswarden.test/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`),
	)
	request.Header.Set("Authorization", "Bearer owat_fixture-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Mcp-Session-Id", "attacker-controlled-session")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	inspects, auths := authenticator.counts()
	if inspects != 0 || auths != 0 || limiter.SubjectCount() != 0 ||
		len(auditRecorder.events) != 0 {
		t.Fatalf(
			"session header reached protected work: inspect=%d auth=%d subjects=%d audit=%d",
			inspects, auths, limiter.SubjectCount(), len(auditRecorder.events),
		)
	}
}

func TestBatchIsRejectedBeforeAuthenticationQuotaAndDomainWork(t *testing.T) {
	for _, protocolVersion := range []string{"", "2025-03-26", "2025-06-18"} {
		name := protocolVersion
		if name == "" {
			name = "missing"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
			authenticator := &fakeAuthenticator{principal: agents.AuthenticatedPrincipal{
				AgentID: "agt_test", TokenID: "tok_test",
				TokenPrefix: "owat_fixture",
			}}
			limiter := agents.NewLimiter(agents.LimiterConfig{})
			auditRecorder := &recordingAudit{}
			credentialService := &fakeCredentialService{}
			handler, err := New(Dependencies{
				Agents: authenticator, AuthAudit: auditRecorder,
				Credentials: credentialService, Assets: &fakeAssetService{},
				Clock: fixedClock{now: now}, Limiter: limiter,
			})
			if err != nil {
				t.Fatal(err)
			}
			body := `[
				{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
					"name":"credential_create","arguments":{
						"space_id":"spc_test","display_name":"one","type":"api_token",
						"payload":{"service":"one","token":"fixture-one"},
						"reason":"test","idempotency_key":"batch-one"}}},
				{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
					"name":"credential_create","arguments":{
						"space_id":"spc_test","display_name":"two","type":"api_token",
						"payload":{"service":"two","token":"fixture-two"},
						"reason":"test","idempotency_key":"batch-two"}}}
			]`
			request := httptest.NewRequest(
				http.MethodPost, "http://opswarden.test/mcp",
				strings.NewReader(body),
			)
			request.Header.Set("Authorization", "Bearer owat_fixture-token")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json, text/event-stream")
			if protocolVersion != "" {
				request.Header.Set("MCP-Protocol-Version", protocolVersion)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf(
					"status=%d body=%s", response.Code, response.Body.String(),
				)
			}
			inspects, auths := authenticator.counts()
			if inspects != 0 || auths != 0 ||
				limiter.SubjectCount() != 0 ||
				credentialService.createCalls != 0 ||
				len(auditRecorder.events) != 0 {
				t.Fatalf(
					"batch reached protected work: inspect=%d auth=%d subjects=%d create=%d audit=%d",
					inspects, auths, limiter.SubjectCount(),
					credentialService.createCalls, len(auditRecorder.events),
				)
			}
		})
	}
}

func TestRateLimitResponseIncludesRetryAfter(t *testing.T) {
	now := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
	limiter := agents.NewLimiter(agents.LimiterConfig{
		Capacity: map[agents.Operation]int{
			agents.OperationAgentRequestWriteSource: 1,
			agents.OperationAgentRequestReadSource:  100,
			agents.OperationAgentRequestRead:        100,
		},
		RefillPerSecond: map[agents.Operation]float64{
			agents.OperationAgentRequestWriteSource: 0.000001,
		},
	})
	handler, err := New(Dependencies{
		Agents: &fakeAuthenticator{principal: agents.AuthenticatedPrincipal{
			AgentID: "agt_test", TokenID: "tok_test", TokenPrefix: "owat_fixture",
		}},
		AuthAudit:   &recordingAudit{},
		Credentials: &fakeCredentialService{}, Assets: &fakeAssetService{},
		Clock: fixedClock{now: now}, Limiter: limiter,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func() *http.Request {
		result := httptest.NewRequest(
			http.MethodPost, "http://opswarden.test/mcp",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`),
		)
		result.Header.Set("Authorization", "Bearer owat_fixture-token")
		result.Header.Set("Content-Type", "application/json")
		result.Header.Set("Accept", "application/json, text/event-stream")
		return result
	}
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, request())
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, request())
	if second.Code != http.StatusTooManyRequests ||
		second.Header().Get("Retry-After") == "" {
		t.Fatalf(
			"status=%d retry-after=%q body=%s",
			second.Code, second.Header().Get("Retry-After"), second.Body.String(),
		)
	}
}

func TestTrustedClockRollbackFailsBeforeFreshAuthentication(t *testing.T) {
	initial := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
	clock := &mutableClock{now: initial}
	authenticator := &fakeAuthenticator{principal: agents.AuthenticatedPrincipal{
		AgentID: "agt_test", TokenID: "tok_test", TokenPrefix: "owat_fixture",
	}}
	credentialService := &fakeCredentialService{get: credentials.Decrypted{
		Metadata: credentials.Metadata{
			ID: "crd_totp", SpaceID: "spc_test",
			DisplayName: "TOTP", Type: credentials.TypeTOTP, Version: 1,
		},
		Payload: json.RawMessage(
			`{"issuer":"Example","account":"alice","seed":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","algorithm":"SHA1","digits":8,"period":30}`,
		),
	}}
	handler, err := New(Dependencies{
		Agents: authenticator, AuthAudit: &recordingAudit{},
		Credentials: credentialService, Assets: &fakeAssetService{},
		Clock: clock, Limiter: agents.NewLimiter(agents.LimiterConfig{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	httpClient := &http.Client{Transport: bearerTransport{
		base: http.DefaultTransport, token: "owat_fixture-token",
	}}
	session, err := mcp.NewClient(
		&mcp.Implementation{Name: "opswarden-test", Version: "1.0.0"}, nil,
	).Connect(
		context.Background(),
		&mcp.StreamableClientTransport{
			Endpoint: server.URL + "/mcp", HTTPClient: httpClient,
			DisableStandaloneSSE: true,
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	beforeInspect, beforeAuth := authenticator.counts()
	clock.set(initial.Add(-time.Minute))
	if _, err := session.CallTool(
		context.Background(),
		&mcp.CallToolParams{
			Name: "totp_generate",
			Arguments: map[string]any{
				"space_id": "spc_test", "credential_id": "crd_totp",
			},
		},
	); err == nil {
		t.Fatal("rollback clock remained usable")
	}
	afterInspect, afterAuth := authenticator.counts()
	if afterInspect != beforeInspect || afterAuth != beforeAuth {
		t.Fatalf(
			"rollback reached fresh auth: inspect=%d->%d auth=%d->%d",
			beforeInspect, afterInspect, beforeAuth, afterAuth,
		)
	}
}
