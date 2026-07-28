package httpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"opswarden/internal/agents"
	"opswarden/internal/audit"
	"opswarden/internal/identity"
	"opswarden/internal/platform"
)

const (
	jwtIssuer        = "opswarden"
	jwtAudience      = "opswarden-web"
	jwtLifetime      = 15 * time.Minute
	jwtMaxTokenBytes = 4096
	jwtKeyContext    = "opswarden/browser-jwt-signing/v1"
	passwordWorkWait = 100 * time.Millisecond
)

var (
	errInvalidJWT = errors.New("invalid browser JWT")
	jwtEncoding   = base64.RawURLEncoding.Strict()
)

type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type jwtClaims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Subject   string `json:"sub"`
	Session   string `json:"sid"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	ExpiresAt int64  `json:"exp"`
}

type jwtSigner struct {
	key   [sha256.Size]byte
	clock platform.Clock
}

func newJWTSigner(masterKey []byte, clock platform.Clock) (*jwtSigner, error) {
	if len(masterKey) != sha256.Size || clock == nil {
		return nil, errInvalidJWT
	}
	var signer jwtSigner
	signer.clock = clock
	reader := hkdf.New(sha256.New, masterKey, nil, []byte(jwtKeyContext))
	if _, err := io.ReadFull(reader, signer.key[:]); err != nil {
		return nil, errInvalidJWT
	}
	return &signer, nil
}

func (signer *jwtSigner) close() {
	if signer != nil {
		clear(signer.key[:])
	}
}

func (signer *jwtSigner) sign(userID string, session identity.Session) (string, error) {
	if signer == nil || userID == "" || session.RawToken == "" {
		return "", errInvalidJWT
	}
	now := signer.clock.Now().UTC().Truncate(time.Second)
	expiry := now.Add(jwtLifetime)
	if session.ExpiresAt.Before(expiry) {
		expiry = session.ExpiresAt.UTC().Truncate(time.Second)
	}
	if now.IsZero() || !expiry.After(now) {
		return "", errInvalidJWT
	}
	header, err := json.Marshal(jwtHeader{Algorithm: "HS256", Type: "JWT"})
	if err != nil {
		return "", errInvalidJWT
	}
	claims, err := json.Marshal(jwtClaims{
		Issuer: jwtIssuer, Audience: jwtAudience, Subject: userID,
		Session: session.RawToken, IssuedAt: now.Unix(), NotBefore: now.Unix(),
		ExpiresAt: expiry.Unix(),
	})
	if err != nil {
		return "", errInvalidJWT
	}
	unsigned := jwtEncoding.EncodeToString(header) + "." + jwtEncoding.EncodeToString(claims)
	mac := hmac.New(sha256.New, signer.key[:])
	_, _ = mac.Write([]byte(unsigned))
	token := unsigned + "." + jwtEncoding.EncodeToString(mac.Sum(nil))
	if len(token) > jwtMaxTokenBytes {
		return "", errInvalidJWT
	}
	return token, nil
}

func (signer *jwtSigner) verify(token string) (jwtClaims, error) {
	if signer == nil || len(token) == 0 || len(token) > jwtMaxTokenBytes {
		return jwtClaims{}, errInvalidJWT
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return jwtClaims{}, errInvalidJWT
	}
	headerBytes, err := decodeJWTPart(parts[0], 256)
	if err != nil {
		return jwtClaims{}, errInvalidJWT
	}
	var header jwtHeader
	if err := decodeCanonicalJSON(headerBytes, &header); err != nil ||
		header.Algorithm != "HS256" || header.Type != "JWT" {
		return jwtClaims{}, errInvalidJWT
	}
	claimsBytes, err := decodeJWTPart(parts[1], 2048)
	if err != nil {
		return jwtClaims{}, errInvalidJWT
	}
	var claims jwtClaims
	if err := decodeCanonicalJSON(claimsBytes, &claims); err != nil {
		return jwtClaims{}, errInvalidJWT
	}
	signature, err := decodeJWTPart(parts[2], sha256.Size)
	if err != nil || len(signature) != sha256.Size {
		return jwtClaims{}, errInvalidJWT
	}
	mac := hmac.New(sha256.New, signer.key[:])
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	validSignature := hmac.Equal(signature, expected)
	clear(expected)
	clear(signature)
	if !validSignature {
		return jwtClaims{}, errInvalidJWT
	}
	now := signer.clock.Now().UTC().Truncate(time.Second)
	if claims.Issuer != jwtIssuer || claims.Audience != jwtAudience ||
		claims.Subject == "" || claims.Session == "" ||
		claims.IssuedAt <= 0 || claims.NotBefore != claims.IssuedAt ||
		claims.ExpiresAt <= claims.IssuedAt ||
		claims.ExpiresAt-claims.IssuedAt > int64(jwtLifetime/time.Second) ||
		now.Unix() < claims.NotBefore || now.Unix() >= claims.ExpiresAt {
		return jwtClaims{}, errInvalidJWT
	}
	return claims, nil
}

func decodeJWTPart(encoded string, maxDecoded int) ([]byte, error) {
	if len(encoded) > jwtMaxTokenBytes {
		return nil, errInvalidJWT
	}
	decoded, err := jwtEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > maxDecoded ||
		jwtEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, errInvalidJWT
	}
	return decoded, nil
}

func decodeCanonicalJSON(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errInvalidJWT
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errInvalidJWT
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return errInvalidJWT
	}
	return nil
}

type beginLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type completeLoginRequest struct {
	ChallengeID  string `json:"challengeId"`
	SecondFactor string `json:"secondFactor"`
}

type bootstrapRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPSeed string `json:"totpSeed"`
}

func (router *Router) handleBootstrapStatus(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" ||
		router.deps.Identity == nil {
		writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
		return
	}
	metadata := requestMetadataFromContext(request.Context())
	sourceIP, err := netip.ParseAddr(metadata.sourceIP)
	if err != nil || !router.deps.Identity.InitialOwnerSourceAllowed(sourceIP) {
		writeAPIError(writer, request, http.StatusForbidden, "PERMISSION_DENIED", false, nil)
		return
	}
	exists, err := router.deps.Identity.HasInitialOwner(request.Context())
	if err != nil {
		writeDomainError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		NeedsInitialOwner bool `json:"needsInitialOwner"`
	}{NeedsInitialOwner: !exists})
}

type reverifyRequest struct {
	Code string `json:"code"`
}

type loginFailureReservation struct {
	router      *Router
	reservation *agents.Reservation
}

type reverifyReservationContextKey struct{}

type reverifyFailureReservation struct {
	router      *Router
	reservation *agents.Reservation
	fingerprint string
}

func (reservation *reverifyFailureReservation) Commit() {
	if reservation != nil && reservation.reservation != nil {
		reservation.reservation.Commit()
	}
}

func (reservation *reverifyFailureReservation) Close() {
	if reservation == nil || reservation.reservation == nil {
		return
	}
	reservation.reservation.Refund(reservation.router.deps.Clock.Now())
}

func (reservation *loginFailureReservation) Commit() {
	if reservation != nil && reservation.reservation != nil {
		reservation.reservation.Commit()
	}
}

func (reservation *loginFailureReservation) Close() {
	if reservation == nil || reservation.reservation == nil {
		return
	}
	reservation.reservation.Refund(reservation.router.deps.Clock.Now())
}

func (router *Router) reserveLoginFailure(
	writer http.ResponseWriter,
	request *http.Request,
	stage string,
	stableIdentity string,
) (*loginFailureReservation, bool) {
	metadata := requestMetadataFromContext(request.Context())
	reservation, decision := router.deps.Limiter.Reserve(
		[]agents.LimitRequest{
			{
				Subject:   "human-" + stage + "-source:" + metadata.sourceIP,
				Operation: agents.OperationLoginSource,
			},
			{
				Subject: "human-" + stage + "-principal:" +
					humanFingerprint(stage+":"+stableIdentity),
				Operation: agents.OperationAuthFailure,
			},
		},
		router.deps.Clock.Now(),
	)
	if !decision.Allowed {
		writeRateLimitError(writer, request, decision)
		return nil, false
	}
	return &loginFailureReservation{
		router: router, reservation: reservation,
	}, true
}

func (router *Router) acquirePasswordWork() bool {
	timer := time.NewTimer(passwordWorkWait)
	defer timer.Stop()
	select {
	case router.passwordWork <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}

func (router *Router) releasePasswordWork() {
	<-router.passwordWork
}

func (router *Router) handleBootstrap(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodPost || router.deps.Identity == nil {
		writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
		return
	}
	metadata := requestMetadataFromContext(request.Context())
	sourceIP, err := netip.ParseAddr(metadata.sourceIP)
	if err != nil || !router.deps.Identity.InitialOwnerSourceAllowed(sourceIP) {
		writeAPIError(writer, request, http.StatusForbidden, "PERMISSION_DENIED", false, nil)
		return
	}
	var input bootstrapRequest
	if err := decodeJSONBody(
		writer, request, defaultBodyLimit, &input,
	); err != nil {
		writeAPIError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", false, nil)
		return
	}
	ownerInput := identity.CreateOwnerInput{
		Email: input.Email, Password: input.Password, TOTPSeed: input.TOTPSeed,
	}
	if err := identity.ValidateInitialOwnerInput(ownerInput); err != nil {
		writeAPIError(
			writer, request, http.StatusBadRequest,
			"INVALID_REQUEST", false, nil,
		)
		return
	}
	exists, err := router.deps.Identity.HasInitialOwner(request.Context())
	if err != nil {
		writeDomainError(writer, request, err)
		return
	}
	if exists {
		writeDomainError(writer, request, identity.ErrInitialOwnerExists)
		return
	}
	decision := router.deps.Limiter.Allow(
		"bootstrap-ip:"+metadata.sourceIP,
		agents.OperationBootstrap, router.deps.Clock.Now(),
	)
	if !decision.Allowed {
		writeRateLimitError(writer, request, decision)
		return
	}
	if !router.acquirePasswordWork() {
		writeRateLimitError(writer, request, agents.Decision{
			RetryAfter: time.Second,
		})
		return
	}
	ownerInput.SourceIP = sourceIP
	ownerInput.RequestID = metadata.requestID
	ownerInput.UserAgent = metadata.userAgent
	result, err := func() (identity.CreateOwnerResult, error) {
		defer router.releasePasswordWork()
		return router.deps.Identity.CreateInitialOwner(
			request.Context(), ownerInput,
		)
	}()
	if err != nil {
		writeDomainError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusCreated, struct {
		UserID        string   `json:"userId"`
		RecoveryCodes []string `json:"recoveryCodes"`
	}{UserID: result.UserID, RecoveryCodes: result.RecoveryCodes})
}

func (router *Router) handleAuth(writer http.ResponseWriter, request *http.Request) {
	if router.deps.Identity == nil || router.jwt == nil {
		writeAPIError(
			writer, request, http.StatusServiceUnavailable,
			"STORAGE_UNAVAILABLE", true, nil,
		)
		return
	}
	switch {
	case request.URL.Path == "/api/v1/auth/reverify" &&
		request.Method == http.MethodPost:
		auth, ok := request.Context().Value(authenticationKey).(authentication)
		if !ok || auth.human == nil || auth.rawSession == "" {
			writeAPIError(
				writer, request, http.StatusUnauthorized,
				"UNAUTHENTICATED", false, nil,
			)
			return
		}
		failureReservation, _ := request.Context().Value(
			reverifyReservationContextKey{},
		).(*reverifyFailureReservation)
		var input reverifyRequest
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil {
			writeAPIError(
				writer, request, http.StatusBadRequest,
				"INVALID_REQUEST", false, nil,
			)
			return
		}
		metadata := requestMetadataFromContext(request.Context())
		principal, err := router.deps.Identity.VerifyRecentTOTPAudited(
			request.Context(), auth.rawSession, input.Code,
			identity.AuthenticationContext{
				RequestID: metadata.requestID, SourceIP: metadata.sourceIP,
				UserAgent: metadata.userAgent,
			},
		)
		if err != nil {
			authenticationFailure := errors.Is(err, identity.ErrInvalidTOTP) ||
				errors.Is(err, identity.ErrTOTPReplay)
			if authenticationFailure && failureReservation != nil {
				failureReservation.Commit()
				observation := router.authFailureGate.observe(
					"auth.totp.reverify", failureReservation.fingerprint,
					router.deps.Clock.Now(),
				)
				if aggregateErr := router.recordAuthenticationFailureAggregate(
					request, "auth.totp.reverify", observation,
				); aggregateErr != nil {
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
			}
			if auditErr := router.recordKnownAuthenticationFailure(
				request, auth.actor, "auth.totp.reverify",
				auth.human.UserID, "REVERIFY_FAILED",
			); auditErr != nil {
				writeAPIError(
					writer, request, http.StatusServiceUnavailable,
					"STORAGE_UNAVAILABLE", true, nil,
				)
				return
			}
			writeDomainError(writer, request, err)
			return
		}
		token, err := router.jwt.sign(principal.UserID, identity.Session{
			RawToken:  auth.rawSession,
			ExpiresAt: router.deps.Clock.Now().UTC().Add(jwtLifetime),
		})
		if err != nil {
			if auditErr := router.recordKnownAuthenticationFailure(
				request, auth.actor, "auth.totp.reverify",
				auth.human.UserID, "JWT_ISSUE_FAILED",
			); auditErr != nil {
				writeAPIError(
					writer, request, http.StatusServiceUnavailable,
					"STORAGE_UNAVAILABLE", true, nil,
				)
				return
			}
			writeAPIError(
				writer, request, http.StatusInternalServerError,
				"INTERNAL_ERROR", false, nil,
			)
			return
		}
		writeJSON(writer, http.StatusOK, struct {
			Token     string    `json:"token"`
			TokenType string    `json:"tokenType"`
			ExpiresAt time.Time `json:"expiresAt"`
		}{
			Token: token, TokenType: "Bearer",
			ExpiresAt: router.deps.Clock.Now().UTC().Add(jwtLifetime),
		})
	case request.URL.Path == "/api/v1/auth/login/begin" &&
		request.Method == http.MethodPost:
		var input beginLoginRequest
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil {
			writeAPIError(
				writer, request, http.StatusBadRequest,
				"INVALID_REQUEST", false, nil,
			)
			return
		}
		reservation, allowed := router.reserveLoginFailure(
			writer, request, "password",
			strings.ToLower(strings.TrimSpace(input.Email)),
		)
		if !allowed {
			return
		}
		defer reservation.Close()
		if !router.acquirePasswordWork() {
			writeRateLimitError(writer, request, agents.Decision{
				RetryAfter: time.Second,
			})
			return
		}
		challenge, err := func() (identity.LoginChallenge, error) {
			defer router.releasePasswordWork()
			return router.deps.Identity.BeginLogin(
				request.Context(), input.Email, input.Password,
			)
		}()
		if err != nil {
			if errors.Is(err, identity.ErrInvalidCredentials) {
				reservation.Commit()
				router.rejectAnonymousAuthentication(
					writer, request, "auth.password", "INVALID_CREDENTIALS",
				)
				return
			}
			writeDomainError(writer, request, err)
			return
		}
		if err := router.recordAuthentication(
			request.Context(), anonymousAuthenticationActor(),
			"auth.password", "authentication", "",
		); err != nil {
			writeAPIError(
				writer, request, http.StatusServiceUnavailable,
				"STORAGE_UNAVAILABLE", true, nil,
			)
			return
		}
		writeJSON(writer, http.StatusOK, struct {
			ChallengeID string    `json:"challengeId"`
			ExpiresAt   time.Time `json:"expiresAt"`
		}{ChallengeID: challenge.ID, ExpiresAt: challenge.ExpiresAt})
	case request.URL.Path == "/api/v1/auth/login/complete" &&
		request.Method == http.MethodPost:
		var input completeLoginRequest
		if err := decodeJSONBody(
			writer, request, defaultBodyLimit, &input,
		); err != nil {
			writeAPIError(
				writer, request, http.StatusBadRequest,
				"INVALID_REQUEST", false, nil,
			)
			return
		}
		reservation, allowed := router.reserveLoginFailure(
			writer, request, "totp", input.ChallengeID,
		)
		if !allowed {
			return
		}
		defer reservation.Close()
		session, err := router.deps.Identity.CompleteLogin(
			request.Context(), input.ChallengeID, input.SecondFactor,
		)
		if err != nil {
			authenticationFailure :=
				errors.Is(err, identity.ErrInvalidChallenge) ||
					errors.Is(err, identity.ErrInvalidTOTP) ||
					errors.Is(err, identity.ErrTOTPReplay) ||
					errors.Is(err, identity.ErrInvalidRecoveryCode)
			if authenticationFailure {
				reservation.Commit()
				router.rejectAnonymousAuthentication(
					writer, request, "auth.totp", "INVALID_SECOND_FACTOR",
				)
				return
			}
			writeDomainError(writer, request, err)
			return
		}
		principal, err := router.deps.Identity.ResolveSession(
			request.Context(), session.RawToken,
		)
		if err != nil {
			_ = router.deps.Identity.Logout(request.Context(), session.RawToken)
			writeDomainError(writer, request, err)
			return
		}
		actor := audit.Actor{
			Type: audit.ActorUser, ID: principal.UserID,
			Fingerprint: humanFingerprint(session.RawToken),
		}
		if err := router.recordAuthentication(
			request.Context(), actor, "auth.totp", "user", principal.UserID,
		); err != nil {
			_ = router.deps.Identity.Logout(request.Context(), session.RawToken)
			writeAPIError(
				writer, request, http.StatusServiceUnavailable,
				"STORAGE_UNAVAILABLE", true, nil,
			)
			return
		}
		token, err := router.jwt.sign(principal.UserID, session)
		if err != nil {
			_ = router.deps.Identity.Logout(request.Context(), session.RawToken)
			writeAPIError(
				writer, request, http.StatusInternalServerError,
				"INTERNAL_ERROR", false, nil,
			)
			return
		}
		tokenExpiresAt := router.deps.Clock.Now().UTC().Add(jwtLifetime)
		if session.ExpiresAt.Before(tokenExpiresAt) {
			tokenExpiresAt = session.ExpiresAt.UTC()
		}
		writeJSON(writer, http.StatusOK, struct {
			Token     string    `json:"token"`
			TokenType string    `json:"tokenType"`
			ExpiresAt time.Time `json:"expiresAt"`
		}{
			Token: token, TokenType: "Bearer",
			ExpiresAt: tokenExpiresAt,
		})
	case request.URL.Path == "/api/v1/auth/refresh" &&
		request.Method == http.MethodPost:
		auth, ok := request.Context().Value(authenticationKey).(authentication)
		if !ok || auth.human == nil || auth.rawSession == "" {
			writeAPIError(
				writer, request, http.StatusUnauthorized,
				"UNAUTHENTICATED", false, nil,
			)
			return
		}
		token, err := router.jwt.sign(auth.human.UserID, identity.Session{
			RawToken:  auth.rawSession,
			ExpiresAt: router.deps.Clock.Now().UTC().Add(jwtLifetime),
		})
		if err != nil {
			if auditErr := router.recordKnownAuthenticationFailure(
				request, auth.actor, "auth.refresh",
				auth.human.UserID, "REFRESH_FAILED",
			); auditErr != nil {
				writeAPIError(
					writer, request, http.StatusServiceUnavailable,
					"STORAGE_UNAVAILABLE", true, nil,
				)
				return
			}
			writeAPIError(
				writer, request, http.StatusInternalServerError,
				"INTERNAL_ERROR", false, nil,
			)
			return
		}
		if err := router.recordAuthentication(
			request.Context(), auth.actor, "auth.refresh", "user", auth.human.UserID,
		); err != nil {
			writeAPIError(
				writer, request, http.StatusServiceUnavailable,
				"STORAGE_UNAVAILABLE", true, nil,
			)
			return
		}
		writeJSON(writer, http.StatusOK, struct {
			Token string `json:"token"`
		}{Token: token})
	case request.URL.Path == "/api/v1/auth/logout" &&
		request.Method == http.MethodPost:
		auth, ok := request.Context().Value(authenticationKey).(authentication)
		if !ok || auth.human == nil {
			writeAPIError(
				writer, request, http.StatusUnauthorized,
				"UNAUTHENTICATED", false, nil,
			)
			return
		}
		metadata := requestMetadataFromContext(request.Context())
		if err := router.deps.Identity.LogoutAudited(
			request.Context(), auth.rawSession,
			identity.AuthenticationContext{
				RequestID: metadata.requestID, SourceIP: metadata.sourceIP,
				UserAgent: metadata.userAgent,
			},
		); err != nil {
			if errors.Is(err, audit.ErrAuditUnavailable) {
				writeDomainError(writer, request, err)
				return
			}
			if auditErr := router.recordKnownAuthenticationFailure(
				request, auth.actor, "auth.logout",
				auth.human.UserID, "LOGOUT_FAILED",
			); auditErr != nil {
				writeAPIError(
					writer, request, http.StatusServiceUnavailable,
					"STORAGE_UNAVAILABLE", true, nil,
				)
				return
			}
			writeDomainError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	default:
		writeAPIError(
			writer, request, http.StatusNotFound,
			"NOT_FOUND", false, nil,
		)
	}
}

func (router *Router) handleMe(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" {
		writeAPIError(writer, request, http.StatusNotFound, "NOT_FOUND", false, nil)
		return
	}
	auth, ok := request.Context().Value(authenticationKey).(authentication)
	if !ok || auth.human == nil || router.deps.Spaces == nil {
		writeAPIError(writer, request, http.StatusUnauthorized, "UNAUTHENTICATED", false, nil)
		return
	}
	principal, err := router.deps.Spaces.ResolveAuthorizationPrincipal(
		request.Context(), *auth.human, "",
	)
	if err != nil {
		writeDomainError(writer, request, err)
		return
	}
	response := struct {
		UserID       string     `json:"userId"`
		SystemRole   string     `json:"systemRole"`
		IssuedAt     time.Time  `json:"issuedAt"`
		RecentTOTPAt *time.Time `json:"recentTotpAt,omitempty"`
	}{
		UserID: auth.human.UserID, SystemRole: principal.SystemRole,
		IssuedAt: auth.human.IssuedAt,
	}
	if !auth.human.RecentTOTPAt.IsZero() {
		recent := auth.human.RecentTOTPAt
		response.RecentTOTPAt = &recent
	}
	writeJSON(writer, http.StatusOK, response)
}
