package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
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
	InitialOwnerSourceAllowed(netip.Addr) bool
	HasInitialOwner(context.Context) (bool, error)
	CreateInitialOwner(context.Context, identity.CreateOwnerInput) (identity.CreateOwnerResult, error)
	BeginLogin(context.Context, string, string) (identity.LoginChallenge, error)
	CompleteLogin(context.Context, string, string) (identity.Session, error)
	ResolveSession(context.Context, string) (identity.SessionPrincipal, error)
	VerifyRecentTOTPAudited(context.Context, string, string, identity.AuthenticationContext) (identity.SessionPrincipal, error)
	Logout(context.Context, string) error
	LogoutAudited(context.Context, string, identity.AuthenticationContext) error
}

type SpaceService interface {
	CreateAudited(context.Context, spaces.MutationContext, spaces.CreateInput) (spaces.Space, error)
	ListForUser(context.Context, identity.SessionPrincipal) ([]spaces.Space, error)
	ListMembers(context.Context, identity.SessionPrincipal, string) ([]spaces.Member, error)
	AddMemberAudited(context.Context, spaces.MutationContext, string, string, spaces.Role) (spaces.Member, error)
	ChangeRoleAudited(context.Context, spaces.MutationContext, string, string, spaces.Role, uint64) (spaces.Member, error)
	RemoveMemberAudited(context.Context, spaces.MutationContext, string, string, uint64) error
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
	Identity          IdentityService
	Spaces            SpaceService
	Credentials       CredentialService
	Assets            AssetService
	Agents            AgentService
	Audit             AuditService
	AuthAudit         AuthenticationAuditRecorder
	Limiter           *agents.Limiter
	Clock             platform.Clock
	Logger            *slog.Logger
	MasterKey         [sha256.Size]byte
	TrustedProxyCIDRs []netip.Prefix
	Fallback          http.Handler
}

type Router struct {
	deps            Dependencies
	jwt             *jwtSigner
	logger          *slog.Logger
	authFailureGate *anonymousFailureGate
	passwordWork    chan struct{}
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
		authFailureGate: newAnonymousFailureGate(),
		passwordWork:    make(chan struct{}, 4),
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
					router.dependencyMiddleware(
						router.rateLimitMiddleware(
							router.authenticationMiddleware(http.HandlerFunc(router.dispatch)),
						),
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
	if request.URL.RawQuery != "" && !routeAllowsQuery(request) {
		writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/api/") &&
		!strings.HasPrefix(request.URL.Path, "/api/v1/") {
		writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
		return
	}
	switch {
	case request.URL.Path == "/api/v1/bootstrap/initial-owner":
		router.handleBootstrap(writer, request)
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

func routeAllowsQuery(request *http.Request) bool {
	if request.Method != http.MethodGet {
		return false
	}
	if request.URL.Path == "/api/v1/audit-events" {
		return true
	}
	segments := pathSegments(request.URL.Path)
	if len(segments) == 5 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "spaces" &&
		(segments[4] == "credentials" || segments[4] == "assets") {
		return true
	}
	return len(segments) == 7 && segments[0] == "api" &&
		segments[1] == "v1" && segments[2] == "spaces" &&
		segments[4] == "assets" && segments[6] == "credentials"
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
	return router.recordAuthenticationOutcome(
		ctx, actor, action, resourceType, resourceID, true, "",
	)
}

func (router *Router) recordAuthenticationOutcome(
	ctx context.Context,
	actor audit.Actor,
	action string,
	resourceType string,
	resourceID string,
	success bool,
	errorCode string,
) error {
	if router.deps.AuthAudit == nil {
		return audit.ErrAuditUnavailable
	}
	metadata := requestMetadataFromContext(ctx)
	event := audit.Event{
		ID:        strings.Replace(newRequestID(), "req_", "aud_", 1),
		RequestID: metadata.requestID, CreatedAt: router.deps.Clock.Now().UTC(),
		Actor: actor, Action: action, ResourceType: resourceType,
		ResourceID: resourceID, SourceIP: metadata.sourceIP,
		UserAgent: metadata.userAgent, Success: success, ErrorCode: errorCode,
	}
	return router.deps.AuthAudit.RecordReadBeforeReturn(ctx, event)
}

func anonymousAuthenticationActor() audit.Actor {
	return audit.Actor{
		Type: audit.ActorAnonymous, ID: "anonymous",
		Fingerprint: humanFingerprint("opswarden/anonymous-auth/v1"),
	}
}

func (router *Router) recordAuthenticationFailure(
	request *http.Request,
	action string,
	errorCode string,
) error {
	return router.recordAuthenticationOutcome(
		request.Context(), anonymousAuthenticationActor(), action,
		"authentication", "", false, errorCode,
	)
}

func (router *Router) recordKnownAuthenticationFailure(
	request *http.Request,
	actor audit.Actor,
	action, resourceID, errorCode string,
) error {
	return router.recordAuthenticationOutcome(
		request.Context(), actor, action, "user", resourceID, false, errorCode,
	)
}

func protectedAuthFailureAction(
	request *http.Request,
) string {
	switch request.URL.Path {
	case "/api/v1/auth/refresh":
		return "auth.refresh"
	case "/api/v1/auth/logout":
		return "auth.logout"
	case "/api/v1/auth/reverify":
		return "auth.totp.reverify"
	default:
		return ""
	}
}

func (router *Router) rejectAnonymousAuthentication(
	writer http.ResponseWriter,
	request *http.Request,
	fallbackAction string,
	errorCode string,
) {
	action := protectedAuthFailureAction(request)
	if action == "" {
		action = fallbackAction
	}
	metadata := requestMetadataFromContext(request.Context())
	observation := router.authFailureGate.observe(
		action, metadata.sourceIP, router.deps.Clock.Now(),
	)
	if err := router.recordAuthenticationFailureAggregate(
		request, action, observation,
	); err != nil {
		writeAPIError(
			writer, request, http.StatusServiceUnavailable,
			"STORAGE_UNAVAILABLE", true, nil,
		)
		return
	}
	if observation.rateLimited {
		writeRateLimitError(writer, request, agents.Decision{
			RetryAfter: observation.retryAfter,
		})
		return
	}
	if observation.recordIndividual {
		if err := router.recordAuthenticationFailure(
			request, action, errorCode,
		); err != nil {
			writeAPIError(
				writer, request, http.StatusServiceUnavailable,
				"STORAGE_UNAVAILABLE", true, nil,
			)
			return
		}
	}
	writeAPIError(
		writer, request, http.StatusUnauthorized,
		"UNAUTHENTICATED", false, nil,
	)
}

func (router *Router) recordAuthenticationFailureAggregate(
	request *http.Request,
	action string,
	observation anonymousFailureObservation,
) error {
	if observation.aggregateCount == 0 {
		return nil
	}
	if router.deps.AuthAudit == nil {
		return audit.ErrAuditUnavailable
	}
	metadata := requestMetadataFromContext(request.Context())
	return router.deps.AuthAudit.RecordReadBeforeReturn(
		request.Context(), audit.Event{
			ID:        strings.Replace(newRequestID(), "req_", "aud_", 1),
			RequestID: metadata.requestID,
			CreatedAt: router.deps.Clock.Now().UTC(),
			Actor:     anonymousAuthenticationActor(),
			Action:    "auth.failure.aggregate", ResourceType: "authentication",
			ResourceID: action, SourceIP: "0.0.0.0",
			Success: false, ErrorCode: "RATE_LIMITED",
			Reason: "operation=" + action +
				";suppressed_count=" + strconv.FormatUint(
				observation.aggregateCount, 10,
			) +
				";window_start=" +
				observation.aggregateStart.UTC().Format(time.RFC3339),
		},
	)
}
