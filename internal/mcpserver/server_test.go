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
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`),
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
