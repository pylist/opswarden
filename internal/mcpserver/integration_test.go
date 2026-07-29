package mcpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"opswarden/internal/agents"
	"opswarden/internal/assets"
	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/credentials"
	"opswarden/internal/cryptobox"
	"opswarden/internal/httpapi"
	"opswarden/internal/storage"
)

const (
	integrationSpaceID = "spc_integration"
	integrationAgentID = "agt_integration"
)

type realParityHarness struct {
	token      string
	db         *storage.DB
	agent      *agents.Service
	credential *credentials.Service
	httpClient *http.Client
	restURL    string
	mcpSession *mcp.ClientSession
	lock       *lockAfterAuthenticationAudit
}

type lockAfterAuthenticationAudit struct {
	delegate AuthenticationAuditRecorder
	conn     *sql.Conn
	mu       sync.Mutex
	armed    bool
	locked   bool
}

func (recorder *lockAfterAuthenticationAudit) RecordReadBeforeReturn(
	ctx context.Context,
	event audit.Event,
) error {
	if err := recorder.delegate.RecordReadBeforeReturn(ctx, event); err != nil {
		return err
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if event.Action != "auth.agent" || !recorder.armed {
		return nil
	}
	recorder.armed = false
	if _, err := recorder.conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	recorder.locked = true
	return nil
}

func (recorder *lockAfterAuthenticationAudit) arm() {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.armed = true
}

func (recorder *lockAfterAuthenticationAudit) release(t *testing.T) {
	t.Helper()
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if !recorder.locked {
		t.Fatal("real SQLite write lock was not acquired")
	}
	if _, err := recorder.conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		t.Fatalf("release SQLite write lock: %v", err)
	}
	recorder.locked = false
}

func TestRealRESTAndMCPServiceParity(t *testing.T) {
	harness := newRealParityHarness(t)
	seed := harness.seedCredential(t, "Shared fixture", "seed-fixture")

	t.Run("get and list return the same real credential", func(t *testing.T) {
		status, code, restGet := harness.rest(
			t, http.MethodGet,
			"/api/v1/spaces/"+integrationSpaceID+"/credentials/"+seed.ID,
			nil, "", "",
		)
		if status != http.StatusOK || code != "" {
			t.Fatalf("REST get status/code = %d/%q", status, code)
		}
		mcpGet := harness.call(t, "credential_get", map[string]any{
			"space_id": integrationSpaceID, "credential_id": seed.ID,
		})
		assertToolSucceeded(t, mcpGet)

		var restDocument struct {
			Metadata struct {
				ID      string `json:"id"`
				SpaceID string `json:"spaceId"`
				Version uint64 `json:"version"`
			} `json:"metadata"`
			Payload credentials.APITokenPayload `json:"payload"`
		}
		decodeTestJSON(t, restGet, &restDocument)
		var mcpDocument struct {
			Metadata struct {
				ID      string `json:"id"`
				SpaceID string `json:"space_id"`
				Version uint64 `json:"version"`
			} `json:"metadata"`
			Payload credentials.APITokenPayload `json:"payload"`
		}
		decodeStructured(t, mcpGet.StructuredContent, &mcpDocument)
		if restDocument.Metadata.ID != mcpDocument.Metadata.ID ||
			restDocument.Metadata.SpaceID != mcpDocument.Metadata.SpaceID ||
			restDocument.Metadata.Version != mcpDocument.Metadata.Version ||
			restDocument.Payload != mcpDocument.Payload {
			t.Fatalf("REST get = %#v, MCP get = %#v", restDocument, mcpDocument)
		}

		status, code, restList := harness.rest(
			t, http.MethodGet,
			"/api/v1/spaces/"+integrationSpaceID+"/credentials",
			nil, "", "",
		)
		if status != http.StatusOK || code != "" {
			t.Fatalf("REST list status/code = %d/%q", status, code)
		}
		mcpList := harness.call(t, "credential_list", map[string]any{
			"space_id": integrationSpaceID,
		})
		assertToolSucceeded(t, mcpList)
		var restPage struct {
			Items []struct {
				ID      string `json:"id"`
				Version uint64 `json:"version"`
			} `json:"items"`
		}
		var mcpPage struct {
			Items []struct {
				ID      string `json:"id"`
				Version uint64 `json:"version"`
			} `json:"items"`
		}
		decodeTestJSON(t, restList, &restPage)
		decodeStructured(t, mcpList.StructuredContent, &mcpPage)
		if fmt.Sprint(restPage.Items) != fmt.Sprint(mcpPage.Items) {
			t.Fatalf("REST list = %#v, MCP list = %#v", restPage, mcpPage)
		}
	})

	t.Run("concealment and version errors use the same stable codes", func(t *testing.T) {
		status, restCode, _ := harness.rest(
			t, http.MethodGet,
			"/api/v1/spaces/spc_outside/credentials/"+seed.ID,
			nil, "", "",
		)
		if status != http.StatusNotFound || restCode != "NOT_FOUND" {
			t.Fatalf("REST concealment = %d/%q", status, restCode)
		}
		mcpResult := harness.call(t, "credential_get", map[string]any{
			"space_id": "spc_outside", "credential_id": seed.ID,
		})
		assertToolCode(t, mcpResult, restCode)
		harness.assertFailureAudits(t, "credential.read", "NOT_FOUND", 2)

		updateBody := []byte(`{"expectedVersion":99,"displayName":"changed"}`)
		status, restCode, _ = harness.rest(
			t, http.MethodPatch,
			"/api/v1/spaces/"+integrationSpaceID+"/credentials/"+seed.ID,
			updateBody, "rest-version", "parity test",
		)
		if status != http.StatusConflict || restCode != "VERSION_CONFLICT" {
			t.Fatalf("REST version = %d/%q", status, restCode)
		}
		mcpResult = harness.call(t, "credential_update", map[string]any{
			"space_id": integrationSpaceID, "credential_id": seed.ID,
			"expected_version": 99, "display_name": "changed",
			"reason": "parity test", "idempotency_key": "mcp-version",
		})
		assertToolCode(t, mcpResult, restCode)
		harness.assertFailureAudits(t, "credential.update", "VERSION_CONFLICT", 2)
	})

	t.Run("idempotency conflicts use the same stable code", func(t *testing.T) {
		firstREST := []byte(
			`{"displayName":"REST one","type":"api_token",` +
				`"payload":{"service":"test","token":"rest-one"}}`,
		)
		status, code, _ := harness.rest(
			t, http.MethodPost,
			"/api/v1/spaces/"+integrationSpaceID+"/credentials",
			firstREST, "rest-idempotency", "parity test",
		)
		if status != http.StatusCreated || code != "" {
			t.Fatalf("REST first create = %d/%q", status, code)
		}
		secondREST := []byte(
			`{"displayName":"REST two","type":"api_token",` +
				`"payload":{"service":"test","token":"rest-two"}}`,
		)
		status, restCode, _ := harness.rest(
			t, http.MethodPost,
			"/api/v1/spaces/"+integrationSpaceID+"/credentials",
			secondREST, "rest-idempotency", "parity test",
		)
		if status != http.StatusConflict || restCode != "IDEMPOTENCY_CONFLICT" {
			t.Fatalf("REST idempotency = %d/%q", status, restCode)
		}

		firstMCP := harness.call(t, "credential_create", map[string]any{
			"space_id": integrationSpaceID, "display_name": "MCP one",
			"type":    "api_token",
			"payload": map[string]any{"service": "test", "token": "mcp-one"},
			"reason":  "parity test", "idempotency_key": "mcp-idempotency",
		})
		assertToolSucceeded(t, firstMCP)
		secondMCP := harness.call(t, "credential_create", map[string]any{
			"space_id": integrationSpaceID, "display_name": "MCP two",
			"type":    "api_token",
			"payload": map[string]any{"service": "test", "token": "mcp-two"},
			"reason":  "parity test", "idempotency_key": "mcp-idempotency",
		})
		assertToolCode(t, secondMCP, restCode)
		harness.assertFailureAudits(t, "credential.create", "IDEMPOTENCY_CONFLICT", 2)
	})

	t.Run("a real SQLite write lock has storage busy parity", func(t *testing.T) {
		harness.lock.arm()
		status, restCode, _ := harness.rest(
			t, http.MethodPost,
			"/api/v1/spaces/"+integrationSpaceID+"/credentials",
			[]byte(
				`{"displayName":"Busy REST","type":"api_token",`+
					`"payload":{"service":"test","token":"busy-rest"}}`,
			),
			"rest-busy", "parity test",
		)
		harness.lock.release(t)
		if status != http.StatusServiceUnavailable || restCode != "STORAGE_UNAVAILABLE" {
			t.Fatalf("REST busy = %d/%q", status, restCode)
		}

		harness.lock.arm()
		mcpResult := harness.call(t, "credential_create", map[string]any{
			"space_id": integrationSpaceID, "display_name": "Busy MCP",
			"type":    "api_token",
			"payload": map[string]any{"service": "test", "token": "busy-mcp"},
			"reason":  "parity test", "idempotency_key": "mcp-busy",
		})
		harness.lock.release(t)
		assertToolCode(t, mcpResult, restCode)
	})
}

func newRealParityHarness(t *testing.T) *realParityHarness {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "opswarden.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Writer.ExecContext(ctx, "PRAGMA busy_timeout = 25"); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 7, 28, 11, 0, 0, 0, time.UTC)
	entropy := make([]byte, 32)
	for index := range entropy {
		entropy[index] = byte(index + 1)
	}
	token := "owat_" + base64.RawURLEncoding.EncodeToString(entropy)
	clear(entropy)
	tokenHash := sha256.Sum256([]byte(token))
	scopes, err := json.Marshal([]authorization.Scope{
		authorization.ScopeAssetList,
		authorization.ScopeAssetRead,
		authorization.ScopeCredentialCreate,
		authorization.ScopeCredentialDelete,
		authorization.ScopeCredentialList,
		authorization.ScopeCredentialRead,
		authorization.ScopeCredentialUpdate,
	})
	if err != nil {
		t.Fatal(err)
	}
	storageTime := now.Add(-time.Minute).Format("2006-01-02T15:04:05.000000000Z")
	if _, err := db.Writer.ExecContext(ctx,
		"INSERT INTO spaces (id, name) VALUES (?, 'Integration')",
		integrationSpaceID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer.ExecContext(ctx, `
		INSERT INTO agents (id, name, created_at, updated_at)
		VALUES (?, 'Integration agent', ?, ?)
	`, integrationAgentID, storageTime, storageTime); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer.ExecContext(ctx, `
		INSERT INTO agent_tokens (
			id, agent_id, token_hash, token_prefix, created_at
		) VALUES ('tok_integration', ?, ?, ?, ?)
	`, integrationAgentID, tokenHash[:],
		token[:len("owat_")+8], storageTime); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer.ExecContext(ctx, `
		INSERT INTO agent_space_grants (
			agent_id, space_id, role, scopes_json, labels_json, created_at
		) VALUES (?, ?, 'editor', ?, '{}', ?)
	`, integrationAgentID, integrationSpaceID, scopes, storageTime); err != nil {
		t.Fatal(err)
	}
	clear(tokenHash[:])
	clear(scopes)

	auditRepository, err := audit.NewRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	auditService, err := audit.NewService(auditRepository)
	if err != nil {
		t.Fatal(err)
	}
	clock := fixedClock{now: now}
	agentService, err := agents.NewService(db, auditRepository, clock)
	if err != nil {
		t.Fatal(err)
	}
	assetService, err := assets.NewService(db, auditRepository, clock)
	if err != nil {
		t.Fatal(err)
	}
	var masterKey [32]byte
	for index := range masterKey {
		masterKey[index] = byte(index + 11)
	}
	credentialService, err := credentials.NewService(
		db, cryptobox.New(masterKey), auditRepository, clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	clear(masterKey[:])

	externalDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = externalDB.Close() })
	externalDB.SetMaxOpenConns(1)
	conn, err := externalDB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = 25"); err != nil {
		t.Fatal(err)
	}
	lockRecorder := &lockAfterAuthenticationAudit{
		delegate: auditService, conn: conn,
	}

	restHandler := httpapi.New(httpapi.Dependencies{
		Credentials: credentialService, Assets: assetService,
		Agents: agentService, Audit: auditService, AuthAudit: lockRecorder,
		Clock: clock, Limiter: agents.NewLimiter(agents.LimiterConfig{}),
	})
	restServer := httptest.NewServer(restHandler)
	t.Cleanup(restServer.Close)
	httpClient := &http.Client{Transport: bearerTransport{
		base: http.DefaultTransport, token: token,
	}}

	mcpHandler, err := New(Dependencies{
		Agents: agentService, Credentials: credentialService,
		Assets: assetService, AuthAudit: lockRecorder, Clock: clock,
		Limiter: agents.NewLimiter(agents.LimiterConfig{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	mcpServer := httptest.NewServer(mcpHandler)
	t.Cleanup(mcpServer.Close)
	session, err := mcp.NewClient(
		&mcp.Implementation{Name: "real-parity-test", Version: "1.0.0"}, nil,
	).Connect(
		ctx,
		&mcp.StreamableClientTransport{
			Endpoint: mcpServer.URL + "/mcp", HTTPClient: httpClient,
			DisableStandaloneSSE: true,
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return &realParityHarness{
		token: token, db: db, agent: agentService,
		credential: credentialService, httpClient: httpClient,
		restURL: restServer.URL, mcpSession: session, lock: lockRecorder,
	}
}

func (harness *realParityHarness) assertFailureAudits(
	t *testing.T,
	action string,
	errorCode string,
	want int,
) {
	t.Helper()
	var got int
	if err := harness.db.Reader.QueryRowContext(context.Background(), `
		SELECT count(*) FROM audit_events
		WHERE action = ?
		  AND json_extract(metadata_json, '$.success') = 0
		  AND json_extract(metadata_json, '$.error_code') = ?
	`, action, errorCode).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s/%s failure audits=%d want=%d", action, errorCode, got, want)
	}
}

func (harness *realParityHarness) seedCredential(
	t *testing.T,
	displayName string,
	token string,
) credentials.MutationResult {
	t.Helper()
	principal, err := harnessAgentPrincipal(harness)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(credentials.APITokenPayload{
		Service: "integration", Token: token,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	result, err := harness.credential.Create(
		context.Background(), principal,
		credentials.CreateInput{
			SpaceID: integrationSpaceID, DisplayName: displayName,
			Type: credentials.TypeAPIToken, Payload: payload,
		},
		credentials.WriteContext{
			Actor: principal.Actor, IdempotencyKey: "seed-" + displayName,
			Reason: "integration fixture",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func harnessAgentPrincipal(
	harness *realParityHarness,
) (credentials.Principal, error) {
	principal, err := harnessAgentAuthentication(harness)
	if err != nil {
		return credentials.Principal{}, err
	}
	authorizationPrincipal := principal.AuthorizationPrincipal()
	return credentials.Principal{
		Agent: &authorizationPrincipal, BoundSpaceID: integrationSpaceID,
		Actor: principal.AuditActor(), RequestID: "req_integration_seed",
		SourceIP: "127.0.0.1", UserAgent: "integration-test",
	}, nil
}

func harnessAgentAuthentication(
	harness *realParityHarness,
) (agents.AuthenticatedPrincipal, error) {
	return harness.agent.InspectAuthentication(context.Background(), harness.token)
}

func (harness *realParityHarness) rest(
	t *testing.T,
	method string,
	path string,
	body []byte,
	idempotencyKey string,
	reason string,
) (int, string, []byte) {
	t.Helper()
	request, err := http.NewRequest(
		method, harness.restURL+path, bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if reason != "" {
		request.Header.Set("X-OpsWarden-Reason", reason)
	}
	response, err := harness.httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(encoded, &envelope)
	return response.StatusCode, envelope.Error.Code, encoded
}

func (harness *realParityHarness) call(
	t *testing.T,
	name string,
	arguments map[string]any,
) *mcp.CallToolResult {
	t.Helper()
	result, err := harness.mcpSession.CallTool(
		context.Background(),
		&mcp.CallToolParams{Name: name, Arguments: arguments},
	)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertToolSucceeded(t *testing.T, result *mcp.CallToolResult) {
	t.Helper()
	if result == nil || result.IsError {
		t.Fatalf("tool result = %#v, want success", result)
	}
}

func assertToolCode(
	t *testing.T,
	result *mcp.CallToolResult,
	want string,
) {
	t.Helper()
	if result == nil || !result.IsError || len(result.Content) != 1 {
		t.Fatalf("tool result = %#v, want %s error", result, want)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || text.Text != want {
		t.Fatalf("tool error = %#v, want %s", result.Content[0], want)
	}
}

func decodeStructured(t *testing.T, value any, destination any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decodeTestJSON(t, encoded, destination)
}

func decodeTestJSON(t *testing.T, encoded []byte, destination any) {
	t.Helper()
	if err := json.Unmarshal(encoded, destination); err != nil {
		t.Fatal(err)
	}
}
