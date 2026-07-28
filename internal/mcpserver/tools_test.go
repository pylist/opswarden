package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"opswarden/internal/agents"
	"opswarden/internal/assets"
	"opswarden/internal/authorization"
	"opswarden/internal/credentials"
)

type fakeCredentialService struct {
	mu sync.Mutex

	listItems []credentials.Metadata
	listNext  string
	get       credentials.Decrypted
	err       error

	createResult credentials.MutationResult
	createCalls  int
	createInput  credentials.CreateInput
	writeContext credentials.WriteContext
	principal    credentials.Principal
}

func (service *fakeCredentialService) List(
	_ context.Context,
	principal credentials.Principal,
	_ credentials.ListFilter,
) ([]credentials.Metadata, string, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.principal = principal
	return service.listItems, service.listNext, service.err
}

func (service *fakeCredentialService) Get(
	_ context.Context,
	principal credentials.Principal,
	_ string,
) (credentials.Decrypted, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.principal = principal
	result := service.get
	result.Payload = append(json.RawMessage(nil), service.get.Payload...)
	return result, service.err
}

func (service *fakeCredentialService) Create(
	_ context.Context,
	principal credentials.Principal,
	input credentials.CreateInput,
	writeContext credentials.WriteContext,
) (credentials.MutationResult, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.createCalls++
	service.principal = principal
	service.createInput = input
	service.createInput.Payload = append(json.RawMessage(nil), input.Payload...)
	service.writeContext = writeContext
	return service.createResult, service.err
}

func (service *fakeCredentialService) Update(
	context.Context,
	credentials.Principal,
	credentials.UpdateInput,
	credentials.WriteContext,
) (credentials.MutationResult, error) {
	return credentials.MutationResult{}, service.err
}

func (service *fakeCredentialService) Delete(
	context.Context,
	credentials.Principal,
	string,
	uint64,
	credentials.WriteContext,
) error {
	return service.err
}

type fakeAssetService struct {
	items []assets.Asset
	item  assets.Asset
	err   error
}

func (service *fakeAssetService) List(
	context.Context,
	assets.Principal,
	assets.ListFilter,
) ([]assets.Asset, string, error) {
	return service.items, "", service.err
}

func (service *fakeAssetService) Get(
	context.Context,
	assets.Principal,
	string,
) (assets.Asset, error) {
	return service.item, service.err
}

type mcpHarness struct {
	t           *testing.T
	server      *httptest.Server
	session     *mcp.ClientSession
	credentials *fakeCredentialService
	audit       *recordingAudit
	auth        *fakeAuthenticator
}

func newToolHarness(
	t *testing.T,
	credentialService *fakeCredentialService,
	limiter *agents.Limiter,
) *mcpHarness {
	t.Helper()
	now := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
	authenticator := &fakeAuthenticator{principal: agents.AuthenticatedPrincipal{
		AgentID: "agt_test", TokenID: "tok_test", TokenPrefix: "owat_fixture",
		Grants: []agents.Grant{{
			SpaceID: "spc_test",
			Scopes: []authorization.Scope{
				authorization.ScopeCredentialList,
				authorization.ScopeCredentialRead,
				authorization.ScopeCredentialCreate,
				authorization.ScopeCredentialUpdate,
				authorization.ScopeCredentialDelete,
				authorization.ScopeAssetList,
				authorization.ScopeAssetRead,
			},
		}},
	}}
	auditRecorder := &recordingAudit{}
	handler, err := New(Dependencies{
		Agents: authenticator, Credentials: credentialService,
		Assets: &fakeAssetService{}, AuthAudit: auditRecorder,
		Clock: fixedClock{now: now}, Limiter: limiter,
	})
	if err != nil {
		t.Fatal(err)
	}
	testServer := httptest.NewServer(handler)
	httpClient := &http.Client{Transport: bearerTransport{
		base: http.DefaultTransport, token: "owat_fixture-token",
	}}
	client := mcp.NewClient(
		&mcp.Implementation{Name: "opswarden-test", Version: "1.0.0"}, nil,
	)
	session, err := client.Connect(
		context.Background(),
		&mcp.StreamableClientTransport{
			Endpoint: testServer.URL + "/mcp", HTTPClient: httpClient,
			DisableStandaloneSSE: true,
		},
		nil,
	)
	if err != nil {
		testServer.Close()
		t.Fatal(err)
	}
	harness := &mcpHarness{
		t: t, server: testServer, session: session,
		credentials: credentialService, audit: auditRecorder,
		auth: authenticator,
	}
	t.Cleanup(func() {
		_ = session.Close()
		testServer.Close()
	})
	return harness
}

func (harness *mcpHarness) call(
	name string,
	arguments map[string]any,
) (*mcp.CallToolResult, error) {
	harness.t.Helper()
	return harness.session.CallTool(
		context.Background(),
		&mcp.CallToolParams{Name: name, Arguments: arguments},
	)
}

func TestCredentialGetReturnsDomainResultAndBindsSpace(t *testing.T) {
	service := &fakeCredentialService{get: credentials.Decrypted{
		Metadata: credentials.Metadata{
			ID: "crd_test", SpaceID: "spc_test", DisplayName: "生产数据库",
			Type: credentials.TypeDatabase, Version: 4,
			Tags: map[string]string{"env": "prod"}, AssetIDs: []string{"ast_1"},
		},
		Payload: json.RawMessage(
			`{"engine":"postgres","host":"db.internal","password":"sensitive"}`,
		),
	}}
	harness := newToolHarness(t, service, agents.NewLimiter(agents.LimiterConfig{}))
	result, err := harness.call("credential_get", map[string]any{
		"space_id": "spc_test", "credential_id": "crd_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %+v", result.Content)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, `"display_name":"生产数据库"`) ||
		!strings.Contains(text, `"password":"sensitive"`) {
		t.Fatalf("unexpected result %s", text)
	}
	if service.principal.BoundSpaceID != "spc_test" ||
		service.principal.Agent == nil ||
		service.principal.Agent.AgentID != "agt_test" {
		t.Fatalf("principal was not freshly bound: %+v", service.principal)
	}
}

func TestCredentialListNeverContainsPayload(t *testing.T) {
	service := &fakeCredentialService{listItems: []credentials.Metadata{{
		ID: "crd_test", SpaceID: "spc_test", DisplayName: "token",
		Type: credentials.TypeAPIToken, Version: 1,
	}}}
	harness := newToolHarness(t, service, agents.NewLimiter(agents.LimiterConfig{}))
	result, err := harness.call("credential_list", map[string]any{
		"space_id": "spc_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if strings.Contains(text, "payload") || strings.Contains(text, "token-value") {
		t.Fatalf("list exposed payload: %s", text)
	}
}

func TestCredentialCreatePassesExactIdempotencyAndReason(t *testing.T) {
	service := &fakeCredentialService{createResult: credentials.MutationResult{
		ID: "crd_created", Version: 1, Status: http.StatusCreated,
	}}
	harness := newToolHarness(t, service, agents.NewLimiter(agents.LimiterConfig{}))
	result, err := harness.call("credential_create", map[string]any{
		"space_id": "spc_test", "display_name": "API",
		"type": "api_token",
		"payload": map[string]any{
			"service": "example", "token": "sensitive-token",
		},
		"reason":          "Hermes deployment",
		"idempotency_key": "idem-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %+v", result.Content)
	}
	if service.writeContext.Reason != "Hermes deployment" ||
		service.writeContext.IdempotencyKey != "idem-create-1" ||
		service.writeContext.Actor.ID != "agt_test" {
		t.Fatalf("wrong write context: %+v", service.writeContext)
	}
	if !strings.Contains(string(service.createInput.Payload), "sensitive-token") {
		t.Fatalf("payload not passed to domain service: %s", service.createInput.Payload)
	}
}

func TestDeleteRequiresExactIDVersionReasonAndIdempotencyKey(t *testing.T) {
	required := map[string]any{
		"space_id": "spc_test", "credential_id": "crd_test",
		"expected_version": float64(2), "reason": "rotation",
		"idempotency_key": "idem-delete-1",
	}
	for _, missing := range []string{
		"credential_id", "expected_version", "reason", "idempotency_key",
	} {
		t.Run(missing, func(t *testing.T) {
			service := &fakeCredentialService{}
			harness := newToolHarness(
				t, service, agents.NewLimiter(agents.LimiterConfig{}),
			)
			input := make(map[string]any, len(required)-1)
			for key, value := range required {
				if key != missing {
					input[key] = value
				}
			}
			result, err := harness.call("credential_delete", input)
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsError ||
				result.Content[0].(*mcp.TextContent).Text != "INVALID_INPUT" {
				t.Fatalf("%s: %+v", missing, result)
			}
		})
	}
}

func TestReadOnlyAgentCannotDiscoverWriteSuccess(t *testing.T) {
	service := &fakeCredentialService{err: credentials.ErrNotFound}
	harness := newToolHarness(t, service, agents.NewLimiter(agents.LimiterConfig{}))
	result, err := harness.call("credential_create", map[string]any{
		"space_id": "spc_test", "display_name": "API", "type": "api_token",
		"payload": map[string]any{"service": "example", "token": "value"},
		"reason":  "test", "idempotency_key": "idem-readonly",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError ||
		result.Content[0].(*mcp.TextContent).Text != "NOT_FOUND" {
		t.Fatalf("authorization was not concealed: %+v", result)
	}
}

func TestStrictInputRejectsDuplicatesCaseAliasesAndDepth(t *testing.T) {
	var input credentialGetInput
	for _, raw := range []string{
		`{"space_id":"spc","space_id":"other","credential_id":"crd"}`,
		`{"space_id":"spc","Space_ID":"other","credential_id":"crd"}`,
		`{"space_id":"spc","credential_id":"crd","extra":true}`,
		`{"space_id":"spc","credential_id":{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":{"m":{"n":{"o":{"p":{"q":1}}}}}}}}}}}}}}}}}}`,
	} {
		if err := decodeExact(json.RawMessage(raw), &input); !errors.Is(
			err, ErrInvalidToolInput,
		) {
			t.Fatalf("accepted %s: %v", raw, err)
		}
	}
}

func TestWriteTransportUsesWriteSourceQuota(t *testing.T) {
	service := &fakeCredentialService{createResult: credentials.MutationResult{
		ID: "crd_created", Version: 1, Status: http.StatusCreated,
	}}
	limiter := agents.NewLimiter(agents.LimiterConfig{
		Capacity: map[agents.Operation]int{
			agents.OperationAgentCredentialWriteSource: 1,
			agents.OperationAgentCredentialWrite:       100,
			agents.OperationAgentRequestReadSource:     100,
			agents.OperationAgentRequestRead:           100,
		},
		RefillPerSecond: map[agents.Operation]float64{
			agents.OperationAgentCredentialWriteSource: 0.000001,
		},
	})
	harness := newToolHarness(t, service, limiter)
	input := map[string]any{
		"space_id": "spc_test", "display_name": "API", "type": "api_token",
		"payload": map[string]any{"service": "example", "token": "value"},
		"reason":  "test", "idempotency_key": "idem-1",
	}
	if first, err := harness.call("credential_create", input); err != nil ||
		first.IsError {
		t.Fatalf("first call failed: result=%+v err=%v", first, err)
	}
	input["idempotency_key"] = "idem-2"
	if _, err := harness.call("credential_create", input); err == nil {
		t.Fatal("second write was not rejected by the transport source quota")
	}
	if service.createCalls != 1 {
		t.Fatalf("domain create calls=%d want 1", service.createCalls)
	}
}

func TestGenerateTOTPOnlyReturnsCodeAndExpiryAfterAudit(t *testing.T) {
	service := &fakeCredentialService{get: credentials.Decrypted{
		Metadata: credentials.Metadata{
			ID: "crd_totp", SpaceID: "spc_test",
			DisplayName: "TOTP", Type: credentials.TypeTOTP, Version: 1,
		},
		Payload: json.RawMessage(
			`{"issuer":"Example","account":"alice","seed":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","algorithm":"SHA1","digits":8,"period":30}`,
		),
	}}
	harness := newToolHarness(t, service, agents.NewLimiter(agents.LimiterConfig{}))
	result, err := harness.call("totp_generate", map[string]any{
		"space_id": "spc_test", "credential_id": "crd_totp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %+v", result.Content)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	var output struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(text), &output); err != nil {
		t.Fatal(err)
	}
	if len(output.Code) != 8 ||
		!strings.Contains(text, `"expiry":"2026-07-28T09:00:30Z"`) ||
		strings.Contains(text, "seed") {
		t.Fatalf("unexpected TOTP output: %s", text)
	}
	found := false
	for _, event := range harness.audit.events {
		if event.Action == "credential.totp.generate" &&
			event.ResourceID == "crd_totp" {
			found = true
		}
		if strings.Contains(event.Reason, "90693936") ||
			strings.Contains(event.Reason, "GEZDGNBV") {
			t.Fatalf("sensitive TOTP material reached audit: %+v", event)
		}
	}
	if !found {
		t.Fatal("missing durable TOTP generation audit")
	}
}

func TestGenerateTOTPMatchesRFC6238SHA1Vector(t *testing.T) {
	code, expiry, err := generateTOTP(credentials.TOTPPayload{
		Seed:      "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		Algorithm: "SHA1", Digits: 8, Period: 30,
	}, time.Unix(59, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if code != "94287082" || !expiry.Equal(time.Unix(60, 0).UTC()) {
		t.Fatalf("code=%s expiry=%s", code, expiry)
	}
}
