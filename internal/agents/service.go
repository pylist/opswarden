package agents

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/identity"
	"opswarden/internal/platform"
	"opswarden/internal/storage"
)

const (
	maxAgentNameBytes        = 256
	maxGrantLabels           = 64
	humanIdempotencyLifetime = 24 * time.Hour
)

type humanIdempotencyResult struct {
	ResourceID string
	Version    uint64
	Status     int
}

type AuditAppender interface {
	AppendTx(context.Context, *sql.Tx, audit.Event) error
}

type Service struct {
	repository *Repository
	audit      AuditAppender
	clock      platform.Clock
}

func NewService(
	db *storage.DB,
	auditAppender AuditAppender,
	clock platform.Clock,
) (*Service, error) {
	repository, err := NewRepository(db)
	if err != nil {
		return nil, err
	}
	if auditAppender == nil {
		return nil, errors.New("agent audit appender is required")
	}
	if clock == nil {
		return nil, errors.New("agent clock is required")
	}
	return &Service{repository: repository, audit: auditAppender, clock: clock}, nil
}

func (service *Service) Create(
	ctx context.Context,
	principal MutationContext,
	input CreateInput,
) (Agent, error) {
	name := strings.TrimSpace(input.Name)
	if !validText(name, maxAgentNameBytes, false) {
		return Agent{}, ErrInvalidInput
	}
	if err := validateMutationContext(principal); err != nil {
		return Agent{}, err
	}
	requestHash, err := humanRequestHash(struct {
		Name string `json:"name"`
	}{Name: name})
	if err != nil {
		return Agent{}, err
	}
	id, err := randomID("agt_", 16)
	if err != nil {
		return Agent{}, errors.New("create agent")
	}
	now := service.clock.Now().UTC()
	if now.IsZero() {
		return Agent{}, ErrInvalidInput
	}
	agent := Agent{ID: id, Name: name, CreatedAt: now, UpdatedAt: now}
	var replayed *Agent
	err = service.repository.withTx(ctx, func(tx *sql.Tx) error {
		if !principal.Session.HasRecentTOTP(now) {
			return identity.ErrRecentTOTPRequired
		}
		human, err := service.repository.humanPrincipalTx(
			ctx, tx, principal.Session, "",
		)
		if err != nil {
			return err
		}
		if err := decisionError(authorization.DecisionForHuman(
			human, authorization.Resource{}, authorization.CreateAgent,
		)); err != nil {
			return err
		}
		result, found, err := checkHumanIdempotency(
			ctx, tx, principal, "agent.create", requestHash, now,
		)
		if err != nil {
			return err
		}
		if found {
			var existing Agent
			var createdAt, updatedAt string
			if err := tx.QueryRowContext(ctx, `
				SELECT id, name, created_at, updated_at FROM agents WHERE id = ?
			`, result.ResourceID).Scan(
				&existing.ID, &existing.Name, &createdAt, &updatedAt,
			); err != nil {
				return errors.New("replay agent create")
			}
			existing.CreatedAt, err = parseAgentTime(createdAt)
			if err != nil {
				return errors.New("replay agent create")
			}
			existing.UpdatedAt, err = parseAgentTime(updatedAt)
			if err != nil {
				return errors.New("replay agent create")
			}
			replayed = &existing
			return nil
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO agents (
				id, name, created_by_user_id, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?)
		`, agent.ID, agent.Name, principal.Session.UserID,
			formatAgentTime(now), formatAgentTime(now)); err != nil {
			return errors.New("create agent")
		}
		event, err := service.auditEvent(
			principal, "agent.create", "", "agent", agent.ID,
			audit.ChangeFields{audit.FieldName},
		)
		if err != nil {
			return ErrAuditUnavailable
		}
		if err := service.audit.AppendTx(ctx, tx, event); err != nil {
			return ErrAuditUnavailable
		}
		return saveHumanIdempotency(
			ctx, tx, principal, "agent.create", requestHash,
			humanIdempotencyResult{
				ResourceID: agent.ID, Version: 1, Status: 201,
			}, now,
		)
	})
	if err != nil {
		return Agent{}, err
	}
	if replayed != nil {
		return *replayed, nil
	}
	return agent, nil
}

func (service *Service) IssueToken(
	ctx context.Context,
	principal MutationContext,
	agentID string,
	expiresAt time.Time,
) (IssuedToken, error) {
	if !validIdentifier(agentID) {
		return IssuedToken{}, ErrAgentNotFound
	}
	if err := validateMutationContext(principal); err != nil {
		return IssuedToken{}, err
	}
	now := service.clock.Now().UTC()
	if now.IsZero() {
		return IssuedToken{}, ErrInvalidInput
	}
	if !expiresAt.IsZero() {
		expiresAt = expiresAt.UTC()
		if !expiresAt.After(now) {
			return IssuedToken{}, ErrInvalidInput
		}
	}
	requestHash, err := humanRequestHash(struct {
		AgentID   string `json:"agent_id"`
		ExpiresAt string `json:"expires_at"`
	}{AgentID: agentID, ExpiresAt: expiresAt.Format(time.RFC3339Nano)})
	if err != nil {
		return IssuedToken{}, err
	}
	var issued IssuedToken
	var replayed *IssuedToken
	err = service.repository.withTx(ctx, func(tx *sql.Tx) error {
		if !principal.Session.HasRecentTOTP(now) {
			return identity.ErrRecentTOTPRequired
		}
		human, err := service.repository.humanPrincipalTx(
			ctx, tx, principal.Session, "",
		)
		if err != nil {
			return err
		}
		if err := decisionError(authorization.DecisionForHuman(
			human, authorization.Resource{ResourceID: agentID},
			authorization.IssueAgentToken,
		)); err != nil {
			return err
		}
		if err := service.repository.requireActiveAgentTx(ctx, tx, agentID); err != nil {
			return err
		}
		result, found, err := checkHumanIdempotency(
			ctx, tx, principal, "agent.token.issue/"+agentID, requestHash, now,
		)
		if err != nil {
			return err
		}
		if found {
			var existing IssuedToken
			var expiry sql.NullString
			if err := tx.QueryRowContext(ctx, `
				SELECT id, token_prefix, expires_at
				FROM agent_tokens WHERE id = ? AND agent_id = ?
			`, result.ResourceID, agentID).Scan(
				&existing.ID, &existing.Prefix, &expiry,
			); err != nil {
				return errors.New("replay agent token issue")
			}
			if expiry.Valid {
				existing.ExpiresAt, err = parseAgentTime(expiry.String)
				if err != nil {
					return errors.New("replay agent token issue")
				}
			}
			existing.Replayed = true
			replayed = &existing
			return nil
		}
		tokenID, err := randomID("tok_", 16)
		if err != nil {
			return errors.New("issue agent token")
		}
		var entropy [32]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return errors.New("issue agent token")
		}
		raw := "owat_" + base64.RawURLEncoding.EncodeToString(entropy[:])
		clear(entropy[:])
		prefix := raw[:len("owat_")+8]
		hash := sha256.Sum256([]byte(raw))
		defer clear(hash[:])
		issued = IssuedToken{
			ID: tokenID, Prefix: prefix, Raw: raw, ExpiresAt: expiresAt,
		}
		var expiry any
		if !expiresAt.IsZero() {
			expiry = formatAgentTime(expiresAt)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO agent_tokens (
				id, agent_id, token_hash, token_prefix, created_at, expires_at
			) VALUES (?, ?, ?, ?, ?, ?)
		`, tokenID, agentID, hash[:], prefix, formatAgentTime(now), expiry); err != nil {
			return errors.New("issue agent token")
		}
		event, err := service.auditEvent(
			principal, "agent.token.issue", "", "agent_token", tokenID,
			audit.ChangeFields{audit.FieldExpiresAt, audit.FieldTokenStatus},
		)
		if err != nil {
			return ErrAuditUnavailable
		}
		if err := service.audit.AppendTx(ctx, tx, event); err != nil {
			return ErrAuditUnavailable
		}
		return saveHumanIdempotency(
			ctx, tx, principal, "agent.token.issue/"+agentID, requestHash,
			humanIdempotencyResult{
				ResourceID: issued.ID, Version: 1, Status: 201,
			}, now,
		)
	})
	if err != nil {
		issued.Raw = ""
		return IssuedToken{}, err
	}
	if replayed != nil {
		issued.Raw = ""
		return *replayed, nil
	}
	return issued, nil
}

func (service *Service) RevokeToken(
	ctx context.Context,
	principal MutationContext,
	tokenID string,
) error {
	if !validIdentifier(tokenID) {
		return ErrTokenNotFound
	}
	if err := validateMutationContext(principal); err != nil {
		return err
	}
	requestHash, err := humanRequestHash(struct {
		TokenID string `json:"token_id"`
	}{TokenID: tokenID})
	if err != nil {
		return err
	}
	now := service.clock.Now().UTC()
	return service.repository.withTx(ctx, func(tx *sql.Tx) error {
		if !principal.Session.HasRecentTOTP(now) {
			return identity.ErrRecentTOTPRequired
		}
		human, err := service.repository.humanPrincipalTx(
			ctx, tx, principal.Session, "",
		)
		if err != nil {
			return err
		}
		if err := decisionError(authorization.DecisionForHuman(
			human, authorization.Resource{ResourceID: tokenID},
			authorization.RevokeAgentToken,
		)); err != nil {
			return err
		}
		_, found, err := checkHumanIdempotency(
			ctx, tx, principal, "agent.token.revoke/"+tokenID, requestHash, now,
		)
		if err != nil || found {
			return err
		}
		var agentID string
		var revokedAt sql.NullString
		err = tx.QueryRowContext(ctx, `
			SELECT agent_id, revoked_at FROM agent_tokens WHERE id = ?
		`, tokenID).Scan(&agentID, &revokedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTokenNotFound
		}
		if err != nil {
			return errors.New("revoke agent token")
		}
		if !revokedAt.Valid {
			if _, err := tx.ExecContext(ctx, `
				UPDATE agent_tokens SET revoked_at = ?
				WHERE id = ? AND revoked_at IS NULL
			`, formatAgentTime(now), tokenID); err != nil {
				return errors.New("revoke agent token")
			}
		}
		event, err := service.auditEvent(
			principal, "agent.token.revoke", "", "agent_token", tokenID,
			audit.ChangeFields{audit.FieldTokenStatus},
		)
		if err != nil {
			return ErrAuditUnavailable
		}
		if err := service.audit.AppendTx(ctx, tx, event); err != nil {
			return ErrAuditUnavailable
		}
		return saveHumanIdempotency(
			ctx, tx, principal, "agent.token.revoke/"+tokenID, requestHash,
			humanIdempotencyResult{
				ResourceID: tokenID, Version: 1, Status: 204,
			}, now,
		)
	})
}

func (service *Service) SetGrant(
	ctx context.Context,
	principal MutationContext,
	agentID string,
	grant Grant,
) error {
	if !validIdentifier(agentID) {
		return ErrAgentNotFound
	}
	normalized, err := normalizeGrant(grant)
	if err != nil {
		return err
	}
	if err := validateMutationContext(principal); err != nil {
		return err
	}
	scopesJSON, labelsJSON, err := encodeGrant(normalized)
	if err != nil {
		return err
	}
	requestHash, err := humanRequestHash(struct {
		AgentID string `json:"agent_id"`
		Grant   Grant  `json:"grant"`
	}{AgentID: agentID, Grant: normalized})
	if err != nil {
		return err
	}
	now := service.clock.Now().UTC()
	return service.repository.withTx(ctx, func(tx *sql.Tx) error {
		if !principal.Session.HasRecentTOTP(now) {
			return identity.ErrRecentTOTPRequired
		}
		human, err := service.repository.humanPrincipalTx(
			ctx, tx, principal.Session, normalized.SpaceID,
		)
		if err != nil {
			return err
		}
		if err := decisionError(authorization.DecisionForHuman(
			human,
			authorization.Resource{SpaceID: normalized.SpaceID, ResourceID: agentID},
			authorization.ManageAgentGrant,
		)); err != nil {
			return err
		}
		if err := service.repository.requireActiveAgentTx(ctx, tx, agentID); err != nil {
			return err
		}
		if err := service.repository.requireActiveSpaceTx(
			ctx, tx, normalized.SpaceID,
		); err != nil {
			return err
		}
		endpoint := "agent.grant.set/" + agentID + "/" + normalized.SpaceID
		_, found, err := checkHumanIdempotency(
			ctx, tx, principal, endpoint, requestHash, now,
		)
		if err != nil || found {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO agent_space_grants (
				agent_id, space_id, role, scopes_json, labels_json, created_at
			) VALUES (?, ?, 'scoped', ?, ?, ?)
			ON CONFLICT(agent_id, space_id) DO UPDATE SET
				role = excluded.role,
				scopes_json = excluded.scopes_json,
				labels_json = excluded.labels_json
		`, agentID, normalized.SpaceID, scopesJSON, labelsJSON,
			formatAgentTime(now)); err != nil {
			return errors.New("set agent grant")
		}
		event, err := service.auditEvent(
			principal, "agent.grant.set", normalized.SpaceID, "agent", agentID,
			audit.ChangeFields{audit.FieldSpaceGrants},
		)
		if err != nil {
			return ErrAuditUnavailable
		}
		if err := service.audit.AppendTx(ctx, tx, event); err != nil {
			return ErrAuditUnavailable
		}
		return saveHumanIdempotency(
			ctx, tx, principal, endpoint, requestHash,
			humanIdempotencyResult{
				ResourceID: agentID, Version: 1, Status: 204,
			}, now,
		)
	})
}

func (service *Service) Authenticate(
	ctx context.Context,
	raw string,
) (AuthenticatedPrincipal, error) {
	if !validRawToken(raw) {
		return AuthenticatedPrincipal{}, authenticationFailed(ErrInvalidToken)
	}
	now := service.clock.Now().UTC()
	if now.IsZero() {
		return AuthenticatedPrincipal{}, authenticationFailed(ErrInvalidClock)
	}
	hash := sha256.Sum256([]byte(raw))
	candidate, found, err := service.repository.tokenByHash(
		ctx, service.repository.db.Reader, hash[:],
	)
	if err != nil {
		clear(hash[:])
		return AuthenticatedPrincipal{}, err
	}
	if !found {
		clear(hash[:])
		return AuthenticatedPrincipal{}, authenticationFailed(ErrInvalidToken)
	}
	if err := validateAuthenticationCandidate(candidate, raw, hash[:], now); err != nil {
		clear(hash[:])
		return AuthenticatedPrincipal{}, err
	}
	var principal AuthenticatedPrincipal
	err = service.repository.withTx(ctx, func(tx *sql.Tx) error {
		token, found, err := service.repository.tokenByHash(ctx, tx, hash[:])
		if err != nil {
			return err
		}
		if !found {
			return authenticationFailed(ErrInvalidToken)
		}
		if err := validateAuthenticationCandidate(
			token, raw, hash[:], now,
		); err != nil {
			return err
		}
		formattedNow := formatAgentTime(now)
		result, err := tx.ExecContext(ctx, `
			UPDATE agent_tokens
			SET last_used_at = CASE
				WHEN last_used_at IS NULL OR last_used_at < ? THEN ?
				ELSE last_used_at
			END
			WHERE id = ?
			  AND token_hash = ?
			  AND revoked_at IS NULL
			  AND created_at <= ?
			  AND (last_used_at IS NULL OR last_used_at <= ?)
			  AND (expires_at IS NULL OR expires_at > ?)
			  AND EXISTS (
				SELECT 1 FROM agents
				WHERE id = agent_tokens.agent_id AND deleted_at IS NULL
			  )
		`, formattedNow, formattedNow, token.ID, hash[:],
			formattedNow, formattedNow, formattedNow)
		if err != nil {
			return ErrAuthenticationUnavailable
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return ErrAuthenticationUnavailable
		}
		if affected != 1 {
			return authenticationFailed(ErrInvalidToken)
		}
		grants, err := service.repository.grantsTx(ctx, tx, token.AgentID)
		if err != nil {
			return err
		}
		principal = AuthenticatedPrincipal{
			AgentID: token.AgentID, TokenID: token.ID,
			TokenPrefix: token.Prefix, Grants: grants,
		}
		return nil
	})
	clear(hash[:])
	if err != nil {
		return AuthenticatedPrincipal{}, err
	}
	return cloneAuthenticatedPrincipal(principal), nil
}

func validateAuthenticationCandidate(
	token tokenRow,
	raw string,
	hash []byte,
	now time.Time,
) error {
	if subtle.ConstantTimeCompare(token.Hash, hash) != 1 {
		return ErrAuthenticationUnavailable
	}
	switch {
	case token.Prefix != raw[:len("owat_")+8]:
		return authenticationFailed(ErrInvalidToken)
	case token.AgentDead:
		return authenticationFailed(ErrAgentDisabled)
	case token.RevokedAt != nil:
		return authenticationFailed(ErrTokenRevoked)
	case token.ExpiresAt != nil && !now.Before(*token.ExpiresAt):
		return authenticationFailed(ErrTokenExpired)
	case now.Before(token.CreatedAt):
		return authenticationFailed(ErrInvalidClock)
	case token.LastUsedAt != nil && now.Before(*token.LastUsedAt):
		return authenticationFailed(ErrInvalidClock)
	default:
		return nil
	}
}

func (service *Service) ListUsage(
	ctx context.Context,
	principal MutationContext,
) ([]Usage, error) {
	if err := validateHumanContext(principal); err != nil {
		return nil, err
	}
	var usage []Usage
	err := service.repository.withTx(ctx, func(tx *sql.Tx) error {
		human, err := service.repository.humanPrincipalTx(
			ctx, tx, principal.Session, "",
		)
		if err != nil {
			return err
		}
		if err := decisionError(authorization.DecisionForHuman(
			human, authorization.Resource{}, authorization.ListAgents,
		)); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `
			SELECT
				a.id,
				a.name,
				count(t.id),
				coalesce(sum(CASE
					WHEN t.revoked_at IS NULL
					  AND (t.expires_at IS NULL OR t.expires_at > ?)
					THEN 1 ELSE 0 END
				), 0),
				max(t.last_used_at)
			FROM agents a
			LEFT JOIN agent_tokens t ON t.agent_id = a.id
			WHERE a.deleted_at IS NULL
			GROUP BY a.id, a.name
			ORDER BY lower(a.name), a.id
		`, formatAgentTime(service.clock.Now().UTC()))
		if err != nil {
			return errors.New("list agent usage")
		}
		defer rows.Close()
		for rows.Next() {
			var row Usage
			var lastUsedAt sql.NullString
			if err := rows.Scan(
				&row.AgentID, &row.Name, &row.TokenCount,
				&row.ActiveTokens, &lastUsedAt,
			); err != nil {
				return errors.New("list agent usage")
			}
			if lastUsedAt.Valid {
				parsed, err := parseAgentTime(lastUsedAt.String)
				if err != nil {
					return errors.New("list agent usage")
				}
				row.LastUsedAt = &parsed
			}
			usage = append(usage, row)
		}
		if err := rows.Err(); err != nil {
			return errors.New("list agent usage")
		}
		return nil
	})
	return usage, err
}

func (service *Service) auditEvent(
	principal MutationContext,
	action, spaceID, resourceType, resourceID string,
	fields audit.ChangeFields,
) (audit.Event, error) {
	id, err := randomID("aud_", 16)
	if err != nil {
		return audit.Event{}, err
	}
	event := audit.Event{
		ID: id, RequestID: principal.RequestID,
		CreatedAt: service.clock.Now().UTC(),
		Actor:     principal.Actor, Action: action, SpaceID: spaceID,
		ResourceType: resourceType, ResourceID: resourceID,
		SourceIP: principal.SourceIP, UserAgent: principal.UserAgent,
		Success: true, ChangeFields: fields,
	}
	if err := audit.Validate(event); err != nil {
		return audit.Event{}, ErrAuditUnavailable
	}
	return event, nil
}

func humanRequestHash(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalidInput
	}
	sum := sha256.Sum256(encoded)
	clear(encoded)
	result := hex.EncodeToString(sum[:])
	clear(sum[:])
	return result, nil
}

func checkHumanIdempotency(
	ctx context.Context,
	tx *sql.Tx,
	principal MutationContext,
	endpoint string,
	requestHash string,
	now time.Time,
) (humanIdempotencyResult, bool, error) {
	if principal.IdempotencyKey == "" {
		return humanIdempotencyResult{}, false, ErrIdempotencyRequired
	}
	keyHash := sha256.Sum256([]byte(principal.IdempotencyKey))
	defer clear(keyHash[:])
	var result humanIdempotencyResult
	var storedHash string
	var expiresAt string
	err := tx.QueryRowContext(ctx, `
		SELECT request_hash, resource_id, resource_version, response_status, expires_at
		FROM human_agent_idempotency_records
		WHERE user_id = ? AND endpoint = ? AND key_hash = ?
	`, principal.Session.UserID, endpoint, keyHash[:]).Scan(
		&storedHash, &result.ResourceID, &result.Version,
		&result.Status, &expiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return humanIdempotencyResult{}, false, nil
	}
	if err != nil {
		return humanIdempotencyResult{}, false, errors.New("read agent idempotency")
	}
	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return humanIdempotencyResult{}, false, errors.New("read agent idempotency")
	}
	if !now.Before(expiry) {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM human_agent_idempotency_records
			WHERE user_id = ? AND endpoint = ? AND key_hash = ?
		`, principal.Session.UserID, endpoint, keyHash[:]); err != nil {
			return humanIdempotencyResult{}, false, errors.New("expire agent idempotency")
		}
		return humanIdempotencyResult{}, false, nil
	}
	if storedHash != requestHash {
		return humanIdempotencyResult{}, false, ErrIdempotencyConflict
	}
	return result, true, nil
}

func saveHumanIdempotency(
	ctx context.Context,
	tx *sql.Tx,
	principal MutationContext,
	endpoint string,
	requestHash string,
	result humanIdempotencyResult,
	now time.Time,
) error {
	if principal.IdempotencyKey == "" {
		return ErrIdempotencyRequired
	}
	id, err := randomID("hid_", 16)
	if err != nil {
		return errors.New("store agent idempotency")
	}
	keyHash := sha256.Sum256([]byte(principal.IdempotencyKey))
	defer clear(keyHash[:])
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO human_agent_idempotency_records (
			id, user_id, endpoint, key_hash, request_hash, resource_id,
			resource_version, response_status, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, principal.Session.UserID, endpoint, keyHash[:], requestHash,
		result.ResourceID, result.Version, result.Status, formatAgentTime(now),
		formatAgentTime(now.Add(humanIdempotencyLifetime))); err != nil {
		return errors.New("store agent idempotency")
	}
	return nil
}

func validateMutationContext(principal MutationContext) error {
	if err := validateHumanContext(principal); err != nil {
		return err
	}
	if principal.IdempotencyKey == "" ||
		!validText(principal.IdempotencyKey, 256, false) {
		return ErrIdempotencyRequired
	}
	return nil
}

func validateHumanContext(principal MutationContext) error {
	if principal.Session.UserID == "" || principal.Session.SessionID == "" {
		return ErrUnauthenticated
	}
	if principal.Actor.Type != audit.ActorUser ||
		principal.Actor.ID != principal.Session.UserID {
		return ErrUnauthenticated
	}
	return nil
}

func decisionError(decision authorization.Decision) error {
	switch err := decision.Err(); {
	case err == nil:
		return nil
	case errors.Is(err, authorization.ErrUnauthenticated):
		return ErrUnauthenticated
	case errors.Is(err, authorization.ErrNotFound):
		return ErrAgentNotFound
	default:
		return ErrForbidden
	}
}

func normalizeGrant(grant Grant) (Grant, error) {
	if !validIdentifier(grant.SpaceID) {
		return Grant{}, ErrInvalidGrant
	}
	if len(grant.Scopes) == 0 || len(grant.Scopes) > 64 {
		return Grant{}, ErrInvalidGrant
	}
	allowed := make(map[authorization.Scope]struct{})
	for _, scope := range authorization.AllScopes() {
		allowed[scope] = struct{}{}
	}
	seen := make(map[authorization.Scope]struct{}, len(grant.Scopes))
	scopes := make([]authorization.Scope, 0, len(grant.Scopes))
	for _, scope := range grant.Scopes {
		if _, exists := allowed[scope]; !exists {
			return Grant{}, ErrInvalidScope
		}
		if _, duplicate := seen[scope]; duplicate {
			continue
		}
		seen[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	slices.Sort(scopes)
	if len(grant.RequiredLabels) > maxGrantLabels {
		return Grant{}, ErrInvalidGrant
	}
	labels := make(map[string]string, len(grant.RequiredLabels))
	for key, value := range grant.RequiredLabels {
		if key != strings.TrimSpace(key) ||
			!validText(key, 128, false) ||
			!validText(value, 512, true) {
			return Grant{}, ErrInvalidGrant
		}
		labels[key] = value
	}
	return Grant{
		SpaceID: grant.SpaceID, Scopes: scopes, RequiredLabels: labels,
	}, nil
}

func cloneLabels(labels map[string]string) map[string]string {
	cloned := make(map[string]string, len(labels))
	for key, value := range labels {
		cloned[key] = value
	}
	return cloned
}

func cloneAuthenticatedPrincipal(principal AuthenticatedPrincipal) AuthenticatedPrincipal {
	cloned := principal
	cloned.Grants = make([]Grant, len(principal.Grants))
	for index, grant := range principal.Grants {
		cloned.Grants[index] = Grant{
			SpaceID:        grant.SpaceID,
			Scopes:         append([]authorization.Scope(nil), grant.Scopes...),
			RequiredLabels: cloneLabels(grant.RequiredLabels),
		}
	}
	return cloned
}

func validRawToken(raw string) bool {
	if len(raw) != len("owat_")+43 || !strings.HasPrefix(raw, "owat_") {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw[len("owat_"):])
	if err != nil || len(decoded) != 32 {
		return false
	}
	canonical := base64.RawURLEncoding.EncodeToString(decoded)
	clear(decoded)
	return canonical == raw[len("owat_"):]
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') {
			continue
		}
		switch character {
		case '-', '_', '.', ':', '@', '/':
			continue
		default:
			return false
		}
	}
	return true
}

func validText(value string, limit int, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character <= 0x1f || (character >= 0x7f && character <= 0x9f) {
			return false
		}
	}
	return true
}

func randomID(prefix string, bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	id := prefix + hex.EncodeToString(raw)
	clear(raw)
	return id, nil
}
