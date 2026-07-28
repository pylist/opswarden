package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"opswarden/internal/agents"
	"opswarden/internal/audit"
)

type responseCapture struct {
	http.ResponseWriter
	status int
}

type verifiedJWTContextKey struct{}

func (capture *responseCapture) WriteHeader(status int) {
	if capture.status == 0 {
		capture.status = status
	}
	capture.ResponseWriter.WriteHeader(status)
}

func (capture *responseCapture) Write(body []byte) (int, error) {
	if capture.status == 0 {
		capture.status = http.StatusOK
	}
	return capture.ResponseWriter.Write(body)
}

func (router *Router) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestID := newRequestID()
		writer.Header().Set("X-Request-ID", requestID)
		metadata := requestMetadata{
			requestID: requestID, sourceIP: router.requestSourceIP(request),
			userAgent: safeUserAgent(request.UserAgent()),
		}
		ctx := context.WithValue(request.Context(), metadataContextKey{}, metadata)
		ctx = context.WithValue(ctx, requestIDKey, requestID)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func (router *Router) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				router.logger.Error("request panic",
					slog.String("request_id", requestID(request.Context())),
					slog.String("method", request.Method),
					slog.String("path", request.URL.Path),
				)
				writeAPIError(
					writer, request, http.StatusInternalServerError,
					"INTERNAL_ERROR", false, nil,
				)
			}
		}()
		next.ServeHTTP(writer, request)
	})
}

func (router *Router) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set(
			"Content-Security-Policy",
			"default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
		)
		if strings.HasPrefix(request.URL.Path, "/api/v1/") {
			writer.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(writer, request)
	})
}

func (router *Router) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := router.deps.Clock.Now()
		capture := &responseCapture{ResponseWriter: writer}
		next.ServeHTTP(capture, request)
		status := capture.status
		if status == 0 {
			status = http.StatusOK
		}
		router.logger.Info("request",
			slog.String("request_id", requestID(request.Context())),
			slog.String("method", request.Method),
			slog.String("path", request.URL.Path),
			slog.Int("status", status),
			slog.Duration("duration", router.deps.Clock.Now().Sub(started)),
		)
	})
}

func (router *Router) dependencyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/api/v1/") &&
			router.deps.AuthAudit == nil {
			writeAPIError(
				writer, request, http.StatusServiceUnavailable,
				"STORAGE_UNAVAILABLE", true, nil,
			)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (router *Router) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		raw, hasBearer := bearerToken(request.Header.Values("Authorization"))
		var verifiedClaims jwtClaims
		hasVerifiedClaims := false
		if !isPublicRoute(request) &&
			strings.HasPrefix(request.URL.Path, "/api/v1/") &&
			hasBearer {
			tokenKind := "human"
			if strings.HasPrefix(raw, "owat_") {
				tokenKind = "agent"
			}
			operation := preAuthenticationOperation(request)
			metadata := requestMetadataFromContext(request.Context())
			reservation, decision := router.deps.Limiter.Reserve(
				[]agents.LimitRequest{{
					Subject: "preauth-source:" + tokenKind + ":" +
						string(operation) + ":" + metadata.sourceIP,
					Operation: agents.OperationRequestSource,
				}},
				router.deps.Clock.Now(),
			)
			if !decision.Allowed {
				writeRateLimitError(writer, request, decision)
				return
			}
			reservation.Commit()
			var strictSubject string
			if tokenKind == "agent" {
				strictSubject = "preauth-agent:" +
					inMemoryBearerFingerprint(raw)
			} else if router.jwt != nil {
				claims, err := router.jwt.verify(raw)
				if err == nil {
					verifiedClaims = claims
					hasVerifiedClaims = true
					strictSubject = "preauth-session:" +
						inMemoryBearerFingerprint(
							claims.Session+"\x00"+claims.Subject+"\x00"+
								string(operation),
						)
				}
			}
			if strictSubject != "" {
				strictReservation, strictDecision := router.deps.Limiter.Reserve(
					[]agents.LimitRequest{{
						Subject: strictSubject, Operation: operation,
					}},
					router.deps.Clock.Now(),
				)
				if !strictDecision.Allowed {
					writeRateLimitError(writer, request, strictDecision)
					return
				}
				strictReservation.Commit()
			}
			if hasVerifiedClaims {
				ctx := context.WithValue(
					request.Context(), verifiedJWTContextKey{}, verifiedClaims,
				)
				request = request.WithContext(ctx)
			}
		}
		if request.Method != http.MethodPost ||
			request.URL.Path != "/api/v1/auth/reverify" {
			next.ServeHTTP(writer, request)
			return
		}
		if !hasBearer || strings.HasPrefix(raw, "owat_") ||
			!hasVerifiedClaims {
			next.ServeHTTP(writer, request)
			return
		}
		metadata := requestMetadataFromContext(request.Context())
		fingerprint := inMemoryBearerFingerprint(
			verifiedClaims.Session + "\x00" + verifiedClaims.Subject,
		)
		reservation, decision := router.deps.Limiter.Reserve(
			[]agents.LimitRequest{
				{
					Subject:   "reverify-source:" + metadata.sourceIP,
					Operation: agents.OperationReverifySource,
				},
				{
					Subject:   "reverify-principal:" + fingerprint,
					Operation: agents.OperationReverifyPrincipal,
				},
			},
			router.deps.Clock.Now(),
		)
		if !decision.Allowed {
			observation := router.authFailureGate.suppress(
				"auth.totp.reverify", fingerprint, router.deps.Clock.Now(),
			)
			if err := router.recordAuthenticationFailureAggregate(
				request, "auth.totp.reverify", observation,
			); err != nil {
				writeAPIError(
					writer, request, http.StatusServiceUnavailable,
					"STORAGE_UNAVAILABLE", true, nil,
				)
				return
			}
			writeRateLimitError(writer, request, decision)
			return
		}
		failureReservation := &reverifyFailureReservation{
			router: router, reservation: reservation, fingerprint: fingerprint,
		}
		defer failureReservation.Close()
		ctx := context.WithValue(
			request.Context(), reverifyReservationContextKey{},
			failureReservation,
		)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func (router *Router) authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if isPublicRoute(request) {
			next.ServeHTTP(writer, request)
			return
		}
		if !strings.HasPrefix(request.URL.Path, "/api/v1/") {
			next.ServeHTTP(writer, request)
			return
		}
		raw, ok := bearerToken(request.Header.Values("Authorization"))
		if !ok {
			router.rejectAnonymousAuthentication(
				writer, request, "auth.jwt", "MISSING_OR_INVALID_BEARER",
			)
			return
		}
		var authenticated authentication
		if strings.HasPrefix(raw, "owat_") {
			if router.deps.Agents == nil || !routeAllowsAgent(request) {
				router.rejectAnonymousAuthentication(
					writer, request, "auth.agent", "INVALID_AGENT_BEARER",
				)
				return
			}
			principal, err := router.deps.Agents.Authenticate(request.Context(), raw)
			if err != nil {
				router.rejectAnonymousAuthentication(
					writer, request, "auth.agent", "INVALID_AGENT_BEARER",
				)
				return
			}
			authenticated.agent = &principal
			authenticated.actor = principal.AuditActor()
			if err := router.recordAuthentication(
				request.Context(), authenticated.actor,
				"auth.agent", "agent", principal.AgentID,
			); err != nil {
				writeAPIError(
					writer, request, http.StatusServiceUnavailable,
					"STORAGE_UNAVAILABLE", true, nil,
				)
				return
			}
		} else {
			if router.jwt == nil || router.deps.Identity == nil {
				router.rejectAnonymousAuthentication(
					writer, request, "auth.jwt", "JWT_UNAVAILABLE",
				)
				return
			}
			claims, verified := request.Context().Value(
				verifiedJWTContextKey{},
			).(jwtClaims)
			if !verified {
				var err error
				claims, err = router.jwt.verify(raw)
				if err != nil {
					router.rejectAnonymousAuthentication(
						writer, request, "auth.jwt", "INVALID_JWT",
					)
					return
				}
			}
			session, err := router.deps.Identity.ResolveSession(
				request.Context(), claims.Session,
			)
			if err != nil || session.UserID != claims.Subject {
				router.rejectAnonymousAuthentication(
					writer, request, "auth.jwt", "INVALID_SESSION",
				)
				return
			}
			authenticated.human = &session
			authenticated.rawSession = claims.Session
			authenticated.actor = audit.Actor{
				Type: audit.ActorUser, ID: session.UserID,
				Fingerprint: humanFingerprint(claims.Session),
			}
			if err := router.recordAuthentication(
				request.Context(), authenticated.actor,
				"auth.jwt", "user", session.UserID,
			); err != nil {
				writeAPIError(
					writer, request, http.StatusServiceUnavailable,
					"STORAGE_UNAVAILABLE", true, nil,
				)
				return
			}
		}
		ctx := context.WithValue(
			request.Context(), authenticationKey, authenticated,
		)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func inMemoryBearerFingerprint(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	fingerprint := hex.EncodeToString(sum[:])
	clear(sum[:])
	return fingerprint
}

func preAuthenticationOperation(request *http.Request) agents.Operation {
	if operation, limited := credentialOperation(request); limited {
		return operation
	}
	switch request.Method {
	case http.MethodGet, http.MethodHead:
		return agents.OperationRequestRead
	default:
		return agents.OperationRequestWrite
	}
}

func credentialOperation(request *http.Request) (agents.Operation, bool) {
	segments := pathSegments(request.URL.Path)
	if len(segments) < 5 || segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "spaces" || segments[4] != "credentials" {
		return "", false
	}
	switch request.Method {
	case http.MethodGet:
		if len(segments) == 5 {
			return agents.OperationCredentialList, true
		}
		if len(segments) == 6 {
			return agents.OperationCredentialRead, true
		}
	case http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete:
		return agents.OperationCredentialWrite, true
	}
	return "", false
}

func writeRateLimitError(
	writer http.ResponseWriter,
	request *http.Request,
	decision agents.Decision,
) {
	writer.Header().Set(
		"Retry-After",
		strconv.Itoa(max(1, int(decision.RetryAfter.Round(time.Second)/time.Second))),
	)
	writeAPIError(
		writer, request, http.StatusTooManyRequests,
		"RATE_LIMITED", true, nil,
	)
}

func isPublicRoute(request *http.Request) bool {
	if request.Method != http.MethodPost {
		return false
	}
	return request.URL.Path == "/api/v1/auth/login/begin" ||
		request.URL.Path == "/api/v1/auth/login/complete" ||
		request.URL.Path == "/api/v1/bootstrap/initial-owner"
}

func routeAllowsAgent(request *http.Request) bool {
	segments := pathSegments(request.URL.Path)
	if len(segments) < 5 || segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "spaces" {
		return false
	}
	switch segments[4] {
	case "credentials":
		return true
	case "assets":
		return request.Method == http.MethodGet
	default:
		return false
	}
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

func requestID(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}

func newRequestID() string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "req_unavailable"
	}
	return "req_" + hex.EncodeToString(random[:])
}

func (router *Router) requestSourceIP(request *http.Request) string {
	direct := directPeerIP(request.RemoteAddr)
	if !addressInPrefixes(direct, router.deps.TrustedProxyCIDRs) {
		return direct.String()
	}
	values := request.Header.Values("X-Forwarded-For")
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 1024 {
		return direct.String()
	}
	parts := strings.Split(values[0], ",")
	if len(parts) == 0 || len(parts) > 16 {
		return direct.String()
	}
	forwarded := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) != part || part == "" {
			return direct.String()
		}
		address, err := netip.ParseAddr(part)
		if err != nil || address.Zone() != "" {
			return direct.String()
		}
		address = address.Unmap()
		if address.String() != part {
			return direct.String()
		}
		forwarded = append(forwarded, address)
	}
	for index := len(forwarded) - 1; index >= 0; index-- {
		if !addressInPrefixes(forwarded[index], router.deps.TrustedProxyCIDRs) {
			return forwarded[index].String()
		}
	}
	return forwarded[0].String()
}

func directPeerIP(remoteAddr string) netip.Addr {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		if address, parseErr := netip.ParseAddr(host); parseErr == nil {
			return address.Unmap()
		}
	}
	if address, parseErr := netip.ParseAddr(remoteAddr); parseErr == nil {
		return address.Unmap()
	}
	return netip.IPv4Unspecified()
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

func pathSegments(path string) []string {
	return strings.Split(strings.TrimPrefix(path, "/"), "/")
}
