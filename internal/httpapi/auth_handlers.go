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
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

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

func (router *Router) handleAuth(writer http.ResponseWriter, request *http.Request) {
	if router.deps.Identity == nil || router.jwt == nil {
		writeAPIError(
			writer, request, http.StatusServiceUnavailable,
			"STORAGE_UNAVAILABLE", true, nil,
		)
		return
	}
	switch {
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
		challenge, err := router.deps.Identity.BeginLogin(
			request.Context(), input.Email, input.Password,
		)
		if err != nil {
			writeDomainError(writer, request, err)
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
		session, err := router.deps.Identity.CompleteLogin(
			request.Context(), input.ChallengeID, input.SecondFactor,
		)
		if err != nil {
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
			request.Context(), actor, "user.authenticate", "user", principal.UserID,
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
			writeAPIError(
				writer, request, http.StatusInternalServerError,
				"INTERNAL_ERROR", false, nil,
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
		if err := router.deps.Identity.Logout(
			request.Context(), auth.rawSession,
		); err != nil {
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
