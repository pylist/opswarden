package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"opswarden/internal/agents"
	"opswarden/internal/assets"
	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/credentials"
	"opswarden/internal/identity"
	"opswarden/internal/platform"
	"opswarden/internal/spaces"
)

type IdentityService interface {
	BeginLogin(context.Context, string, string) (identity.LoginChallenge, error)
	CompleteLogin(context.Context, string, string) (identity.Session, error)
	ResolveSession(context.Context, string) (identity.SessionPrincipal, error)
	Logout(context.Context, string) error
}

type SpaceService interface {
	CreateAudited(context.Context, spaces.MutationContext, spaces.CreateInput) (spaces.Space, error)
	ListForUser(context.Context, identity.SessionPrincipal) ([]spaces.Space, error)
	ResolveAuthorizationPrincipal(
		context.Context,
		identity.SessionPrincipal,
		string,
	) (authorization.HumanPrincipal, error)
}

type CredentialService interface {
	List(context.Context, credentials.Principal, credentials.ListFilter) ([]credentials.Metadata, string, error)
	Get(context.Context, credentials.Principal, string) (credentials.Decrypted, error)
	Create(context.Context, credentials.Principal, credentials.CreateInput, credentials.WriteContext) (credentials.MutationResult, error)
	Update(context.Context, credentials.Principal, credentials.UpdateInput, credentials.WriteContext) (credentials.MutationResult, error)
	Delete(context.Context, credentials.Principal, string, uint64, credentials.WriteContext) error
	Restore(context.Context, credentials.Principal, string, uint64, credentials.WriteContext) (credentials.Metadata, error)
}

type AssetService interface {
	List(context.Context, assets.Principal, assets.ListFilter) ([]assets.Asset, string, error)
	Get(context.Context, assets.Principal, string) (assets.Asset, error)
	Create(context.Context, assets.Principal, assets.CreateInput) (assets.Asset, error)
	Update(context.Context, assets.Principal, assets.UpdateInput) (assets.Asset, error)
	Delete(context.Context, assets.Principal, string, uint64) error
	ListCredentialMetadata(
		context.Context,
		assets.Principal,
		string,
		assets.CredentialListPage,
	) ([]credentials.Metadata, string, error)
}

type AgentService interface {
	agents.Authenticator
	Create(context.Context, agents.MutationContext, agents.CreateInput) (agents.Agent, error)
	IssueToken(context.Context, agents.MutationContext, string, time.Time) (agents.IssuedToken, error)
	RevokeToken(context.Context, agents.MutationContext, string) error
	SetGrant(context.Context, agents.MutationContext, string, agents.Grant) error
	ListUsage(context.Context, agents.MutationContext) ([]agents.Usage, error)
}

type AuditService interface {
	List(context.Context, audit.Filter) ([]audit.Event, audit.Cursor, error)
}

type AuthenticationAuditRecorder interface {
	RecordReadBeforeReturn(context.Context, audit.Event) error
}

type Dependencies struct {
	Identity    IdentityService
	Spaces      SpaceService
	Credentials CredentialService
	Assets      AssetService
	Agents      AgentService
	Audit       AuditService
	AuthAudit   AuthenticationAuditRecorder
	Limiter     *agents.Limiter
	Clock       platform.Clock
	Logger      *slog.Logger
	MasterKey   [sha256.Size]byte
	Fallback    http.Handler
}

type Router struct {
	deps   Dependencies
	jwt    *jwtSigner
	logger *slog.Logger
}

type authentication struct {
	human      *identity.SessionPrincipal
	agent      *agents.AuthenticatedPrincipal
	rawSession string
	actor      audit.Actor
}

type requestContextKey uint8

const (
	requestIDKey requestContextKey = iota
	authenticationKey
)

func New(dependencies Dependencies) http.Handler {
	if dependencies.Clock == nil {
		dependencies.Clock = platform.SystemClock{}
	}
	if dependencies.Logger == nil {
		dependencies.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if dependencies.Limiter == nil {
		dependencies.Limiter = agents.NewLimiter(agents.LimiterConfig{})
	}
	signer, err := newJWTSigner(dependencies.MasterKey[:], dependencies.Clock)
	clear(dependencies.MasterKey[:])
	router := &Router{
		deps: dependencies, jwt: signer, logger: dependencies.Logger,
	}
	if err != nil {
		router.jwt = nil
	}
	return router
}

func (router *Router) Close() error {
	router.jwt.close()
	return nil
}

func (router *Router) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	router.requestIDMiddleware(
		router.recoveryMiddleware(
			router.securityHeadersMiddleware(
				router.loggingMiddleware(
					router.rateLimitMiddleware(
						router.authenticationMiddleware(http.HandlerFunc(router.dispatch)),
					),
				),
			),
		),
	).ServeHTTP(writer, request)
}

func (router *Router) dispatch(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawPath != "" || strings.Contains(request.URL.Path, "//") ||
		(request.URL.Path != "/" && strings.HasSuffix(request.URL.Path, "/")) {
		writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/api/") &&
		!strings.HasPrefix(request.URL.Path, "/api/v1/") {
		writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
		return
	}
	switch {
	case strings.HasPrefix(request.URL.Path, "/api/v1/auth/"):
		router.handleAuth(writer, request)
	case request.URL.Path == "/api/v1/me":
		router.handleMe(writer, request)
	case request.URL.Path == "/api/v1/spaces":
		router.handleSpaces(writer, request)
	case strings.HasPrefix(request.URL.Path, "/api/v1/spaces/"):
		router.handleSpaceResource(writer, request)
	case request.URL.Path == "/api/v1/agents" ||
		strings.HasPrefix(request.URL.Path, "/api/v1/agents/"):
		router.handleAgents(writer, request)
	case request.URL.Path == "/api/v1/audit-events":
		router.handleAudit(writer, request)
	case strings.HasPrefix(request.URL.Path, "/api/"):
		writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
	default:
		if router.deps.Fallback != nil {
			router.deps.Fallback.ServeHTTP(writer, request)
			return
		}
		http.NotFound(writer, request)
	}
}

func (router *Router) principal(
	ctx context.Context,
	spaceID string,
) (credentials.Principal, error) {
	auth, ok := ctx.Value(authenticationKey).(authentication)
	if !ok {
		return credentials.Principal{}, authorization.ErrUnauthenticated
	}
	meta := requestMetadataFromContext(ctx)
	principal := credentials.Principal{
		Actor: auth.actor, RequestID: meta.requestID,
		SourceIP: meta.sourceIP, UserAgent: meta.userAgent,
		BoundSpaceID: spaceID,
	}
	switch {
	case auth.human != nil:
		if router.deps.Spaces == nil {
			return credentials.Principal{}, authorization.ErrUnauthenticated
		}
		human, err := router.deps.Spaces.ResolveAuthorizationPrincipal(
			ctx, *auth.human, spaceID,
		)
		if err != nil {
			return credentials.Principal{}, err
		}
		principal.Human = &human
	case auth.agent != nil:
		agent := auth.agent.AuthorizationPrincipal()
		principal.Agent = &agent
	default:
		return credentials.Principal{}, authorization.ErrUnauthenticated
	}
	return principal, nil
}

func humanFingerprint(rawSession string) string {
	sum := sha256.Sum256([]byte(rawSession))
	fingerprint := hex.EncodeToString(sum[:8])
	clear(sum[:])
	return fingerprint
}

func (router *Router) recordAuthentication(
	ctx context.Context,
	actor audit.Actor,
	action string,
	resourceType string,
	resourceID string,
) error {
	if router.deps.AuthAudit == nil {
		return nil
	}
	metadata := requestMetadataFromContext(ctx)
	event := audit.Event{
		ID:        strings.Replace(newRequestID(), "req_", "aud_", 1),
		RequestID: metadata.requestID, CreatedAt: router.deps.Clock.Now().UTC(),
		Actor: actor, Action: action, ResourceType: resourceType,
		ResourceID: resourceID, SourceIP: metadata.sourceIP,
		UserAgent: metadata.userAgent, Success: true,
	}
	return router.deps.AuthAudit.RecordReadBeforeReturn(ctx, event)
}
