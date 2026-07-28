package mcpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"opswarden/internal/agents"
	"opswarden/internal/assets"
	"opswarden/internal/audit"
	"opswarden/internal/credentials"
	"opswarden/internal/platform"
)

const maxRequestBytes = int64(1 << 20)

type AuthenticationAuditRecorder interface {
	RecordReadBeforeReturn(context.Context, audit.Event) error
}

type CredentialService interface {
	List(context.Context, credentials.Principal, credentials.ListFilter) ([]credentials.Metadata, string, error)
	Get(context.Context, credentials.Principal, string) (credentials.Decrypted, error)
	Create(context.Context, credentials.Principal, credentials.CreateInput, credentials.WriteContext) (credentials.MutationResult, error)
	Update(context.Context, credentials.Principal, credentials.UpdateInput, credentials.WriteContext) (credentials.MutationResult, error)
	Delete(context.Context, credentials.Principal, string, uint64, credentials.WriteContext) error
}

type AssetService interface {
	List(context.Context, assets.Principal, assets.ListFilter) ([]assets.Asset, string, error)
	Get(context.Context, assets.Principal, string) (assets.Asset, error)
}

type Dependencies struct {
	Agents            agents.Authenticator
	Credentials       CredentialService
	Assets            AssetService
	AuthAudit         AuthenticationAuditRecorder
	Limiter           *agents.Limiter
	Clock             platform.Clock
	TrustedProxyCIDRs []netip.Prefix
}

type requestContext struct {
	principal agents.AuthenticatedPrincipal
	actor     audit.Actor
	requestID string
	sourceIP  string
	userAgent string
}

type requestContextKey struct{}

func New(dependencies Dependencies) (http.Handler, error) {
	if dependencies.Agents == nil {
		return nil, errors.New("MCP Agent authenticator is required")
	}
	if dependencies.AuthAudit == nil {
		return nil, errors.New("MCP authentication audit recorder is required")
	}
	if dependencies.Credentials == nil {
		return nil, errors.New("MCP credential service is required")
	}
	if dependencies.Assets == nil {
		return nil, errors.New("MCP asset service is required")
	}
	if dependencies.Clock == nil {
		return nil, errors.New("MCP clock is required")
	}
	if dependencies.Limiter == nil {
		dependencies.Limiter = agents.NewLimiter(agents.LimiterConfig{})
	}

	server := mcp.NewServer(
		&mcp.Implementation{Name: "opswarden", Version: "1.0.0"},
		&mcp.ServerOptions{
			Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
			GetSessionID: func() string {
				return ""
			},
			Capabilities: &mcp.ServerCapabilities{
				Tools: &mcp.ToolCapabilities{},
			},
		},
	)
	if err := registerTools(server, dependencies); err != nil {
		return nil, err
	}
	stream := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)
	return &handler{dependencies: dependencies, stream: stream}, nil
}

type handler struct {
	dependencies Dependencies
	stream       http.Handler
}

func (handler *handler) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	requestID := newID("req_")
	writer.Header().Set("X-Request-ID", requestID)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Referrer-Policy", "no-referrer")

	if request.URL.Path != "/mcp" || request.URL.RawPath != "" ||
		request.URL.RawQuery != "" {
		writeTransportError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeTransportError(
			writer, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", requestID,
		)
		return
	}
	if request.Header.Get("Origin") != "" {
		writeTransportError(
			writer, http.StatusForbidden, "ORIGIN_NOT_ALLOWED", requestID,
		)
		return
	}
	if request.Header.Get("Content-Encoding") != "" {
		writeTransportError(
			writer, http.StatusUnsupportedMediaType, "INVALID_REQUEST", requestID,
		)
		return
	}
	contentType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		writeTransportError(
			writer, http.StatusUnsupportedMediaType, "INVALID_REQUEST", requestID,
		)
		return
	}
	if !acceptsMCPResponse(request.Header.Values("Accept")) {
		writeTransportError(
			writer, http.StatusNotAcceptable, "INVALID_REQUEST", requestID,
		)
		return
	}
	if len(request.Header.Values("Mcp-Session-Id")) != 0 {
		writeTransportError(
			writer, http.StatusBadRequest, "INVALID_REQUEST", requestID,
		)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	encoded, err := io.ReadAll(request.Body)
	if err != nil || len(bytes.TrimSpace(encoded)) == 0 {
		writeTransportError(
			writer, http.StatusRequestEntityTooLarge, "INVALID_REQUEST", requestID,
		)
		return
	}
	envelope, err := decodeMCPEnvelope(encoded)
	if err != nil {
		writeTransportError(
			writer, http.StatusBadRequest, "INVALID_REQUEST", requestID,
		)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(encoded))
	raw, ok := bearerToken(request.Header.Values("Authorization"))
	sourceIP := requestSourceIP(request, handler.dependencies.TrustedProxyCIDRs)
	now := handler.dependencies.Clock.Now().UTC()
	sourceReservation, sourceDecision := handler.dependencies.Limiter.Reserve(
		[]agents.LimitRequest{{
			Subject:   "mcp-preauth-source:" + sourceIP,
			Operation: agents.OperationAgentRequestWriteSource,
		}},
		now,
	)
	if !sourceDecision.Allowed {
		writeRateLimitError(writer, sourceDecision, requestID)
		return
	}
	sourceReservation.Commit()
	operation, sourceOperation := mcpRequestOperation(envelope)
	// Apply the same credential list/read/write source buckets used by REST once
	// the bounded JSON-RPC envelope reveals the requested tool.
	operationSourceReservation, sourceDecision :=
		handler.dependencies.Limiter.Reserve(
			[]agents.LimitRequest{{
				Subject:   "mcp-operation-source:" + sourceIP,
				Operation: sourceOperation,
			}},
			now,
		)
	if !sourceDecision.Allowed {
		writeRateLimitError(writer, sourceDecision, requestID)
		return
	}
	operationSourceReservation.Commit()
	if !ok || !strings.HasPrefix(raw, "owat_") {
		handler.rejectAuthentication(writer, request, requestID, sourceIP, now)
		return
	}
	inspected, err := handler.dependencies.Agents.InspectAuthentication(
		request.Context(), raw,
	)
	if err != nil || inspected.AgentID == "" || inspected.TokenID == "" {
		handler.rejectAuthentication(writer, request, requestID, sourceIP, now)
		return
	}
	strictSubject := "mcp-preauth-agent:" + bearerFingerprint(
		inspected.AgentID+"\x00"+inspected.TokenID+"\x00"+raw,
	)
	strictReservation, strictDecision := handler.dependencies.Limiter.Reserve(
		[]agents.LimitRequest{{
			Subject: strictSubject, Operation: operation,
		}},
		now,
	)
	if !strictDecision.Allowed {
		writeRateLimitError(writer, strictDecision, requestID)
		return
	}
	strictReservation.Commit()
	principal, err := handler.dependencies.Agents.Authenticate(request.Context(), raw)
	if err != nil || principal.AgentID != inspected.AgentID ||
		principal.TokenID != inspected.TokenID {
		handler.rejectAuthentication(writer, request, requestID, sourceIP, now)
		return
	}
	actor := principal.AuditActor()
	if err := handler.dependencies.AuthAudit.RecordReadBeforeReturn(
		request.Context(),
		audit.Event{
			ID: newID("aud_"), RequestID: requestID, CreatedAt: now,
			Actor: actor, Action: "auth.agent", ResourceType: "agent",
			ResourceID: principal.AgentID, SourceIP: sourceIP,
			UserAgent: safeUserAgent(request.UserAgent()), Success: true,
		},
	); err != nil {
		writeTransportError(
			writer, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", requestID,
		)
		return
	}
	ctx := context.WithValue(request.Context(), requestContextKey{}, requestContext{
		principal: principal, actor: actor, requestID: requestID,
		sourceIP: sourceIP, userAgent: safeUserAgent(request.UserAgent()),
	})
	handler.stream.ServeHTTP(writer, request.WithContext(ctx))
}

func acceptsMCPResponse(values []string) bool {
	if len(values) != 1 {
		return false
	}
	var acceptsJSON, acceptsEvents bool
	for _, part := range strings.Split(values[0], ",") {
		mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil {
			return false
		}
		switch mediaType {
		case "application/json":
			acceptsJSON = true
		case "text/event-stream":
			acceptsEvents = true
		}
	}
	return acceptsJSON && acceptsEvents
}

type mcpEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func decodeMCPEnvelope(encoded []byte) (mcpEnvelope, error) {
	var envelope mcpEnvelope
	if err := decodeExact(encoded, &envelope); err != nil ||
		envelope.JSONRPC != "2.0" || envelope.Method == "" ||
		strings.TrimSpace(envelope.Method) != envelope.Method {
		return mcpEnvelope{}, ErrInvalidToolInput
	}
	if len(envelope.Params) != 0 &&
		(len(bytes.TrimSpace(envelope.Params)) == 0 ||
			bytes.TrimSpace(envelope.Params)[0] != '{') {
		return mcpEnvelope{}, ErrInvalidToolInput
	}
	return envelope, nil
}

func mcpRequestOperation(envelope mcpEnvelope) (agents.Operation, agents.Operation) {
	if envelope.Method == "tools/call" {
		var params struct {
			Meta      json.RawMessage `json:"_meta,omitempty"`
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments,omitempty"`
		}
		if decodeExact(envelope.Params, &params) != nil {
			return agents.OperationAgentRequestRead,
				agents.OperationAgentRequestReadSource
		}
		switch params.Name {
		case "credential_list":
			return agents.OperationAgentCredentialList,
				agents.OperationAgentCredentialListSource
		case "credential_get", "totp_generate":
			return agents.OperationAgentCredentialRead,
				agents.OperationAgentCredentialReadSource
		case "credential_create", "credential_update", "credential_delete":
			return agents.OperationAgentCredentialWrite,
				agents.OperationAgentCredentialWriteSource
		}
	}
	return agents.OperationAgentRequestRead, agents.OperationAgentRequestReadSource
}

func (handler *handler) rejectAuthentication(
	writer http.ResponseWriter,
	request *http.Request,
	requestID string,
	sourceIP string,
	now time.Time,
) {
	reservation, decision := handler.dependencies.Limiter.Reserve(
		[]agents.LimitRequest{{
			Subject:   "mcp-auth-failure:" + sourceIP,
			Operation: agents.OperationAuthFailure,
		}},
		now,
	)
	if !decision.Allowed {
		writeRateLimitError(writer, decision, requestID)
		return
	}
	reservation.Commit()
	anonymous := anonymousActor()
	if err := handler.dependencies.AuthAudit.RecordReadBeforeReturn(
		request.Context(),
		audit.Event{
			ID: newID("aud_"), RequestID: requestID, CreatedAt: now,
			Actor: anonymous, Action: "auth.agent",
			ResourceType: "authentication", SourceIP: sourceIP,
			UserAgent: safeUserAgent(request.UserAgent()), Success: false,
			ErrorCode: "INVALID_AGENT_BEARER",
		},
	); err != nil {
		writeTransportError(
			writer, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", requestID,
		)
		return
	}
	writeTransportError(writer, http.StatusUnauthorized, "UNAUTHENTICATED", requestID)
}

func writeRateLimitError(
	writer http.ResponseWriter,
	decision agents.Decision,
	requestID string,
) {
	seconds := max(
		1,
		int((decision.RetryAfter+time.Second-1)/time.Second),
	)
	writer.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeTransportError(
		writer, http.StatusTooManyRequests, "RATE_LIMITED", requestID,
	)
}

func bearerToken(values []string) (string, bool) {
	if len(values) != 1 || strings.Contains(values[0], ",") ||
		!strings.HasPrefix(values[0], "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || strings.TrimSpace(token) != token ||
		strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func directPeerIP(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	if net.ParseIP(remoteAddress) != nil {
		return remoteAddress
	}
	return "0.0.0.0"
}

func requestSourceIP(
	request *http.Request,
	trustedProxyCIDRs []netip.Prefix,
) string {
	direct := directPeerIP(request.RemoteAddr)
	address, err := netip.ParseAddr(direct)
	if err != nil || !addressInPrefixes(address.Unmap(), trustedProxyCIDRs) {
		return direct
	}
	values := request.Header.Values("X-Forwarded-For")
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 1024 {
		return direct
	}
	parts := strings.Split(values[0], ",")
	if len(parts) == 0 || len(parts) > 16 {
		return direct
	}
	forwarded := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) != part || part == "" {
			return direct
		}
		address, err := netip.ParseAddr(part)
		if err != nil || address.Zone() != "" {
			return direct
		}
		address = address.Unmap()
		if address.String() != part {
			return direct
		}
		forwarded = append(forwarded, address)
	}
	for index := len(forwarded) - 1; index >= 0; index-- {
		if !addressInPrefixes(forwarded[index], trustedProxyCIDRs) {
			return forwarded[index].String()
		}
	}
	return forwarded[0].String()
}

func addressInPrefixes(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.IsValid() && prefix.Contains(address) {
			return true
		}
	}
	return false
}

func safeUserAgent(value string) string {
	if len(value) > audit.MaxAuditTextBytes {
		return ""
	}
	for _, character := range value {
		if character <= 0x1f || (character >= 0x7f && character <= 0x9f) {
			return ""
		}
	}
	return value
}

func bearerFingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	result := hex.EncodeToString(sum[:])
	clear(sum[:])
	return result
}

func anonymousActor() audit.Actor {
	return audit.Actor{
		Type: audit.ActorAnonymous, ID: "anonymous",
		Fingerprint: bearerFingerprint("opswarden/mcp/anonymous/v1")[:16],
	}
}

func newID(prefix string) string {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return prefix + "unavailable"
	}
	return prefix + hex.EncodeToString(entropy[:])
}

func writeTransportError(
	writer http.ResponseWriter,
	status int,
	code string,
	requestID string,
) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"requestId"`
		} `json:"error"`
	}{Error: struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"requestId"`
	}{Code: code, Message: "The request could not be completed.", RequestID: requestID}})
}
