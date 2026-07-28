package agents

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/platform"
	"opswarden/internal/storage"
)

const (
	maxAgentNameBytes = 256
	maxGrantLabels    = 64
)

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
	id, err := randomID("agt_", 16)
	if err != nil {
		return Agent{}, errors.New("create agent")
	}
	now := service.clock.Now().UTC()
	if now.IsZero() {
		return Agent{}, ErrInvalidInput
	}
	agent := Agent{ID: id, Name: name, CreatedAt: now, UpdatedAt: now}
	err = service.repository.withTx(ctx, func(tx *sql.Tx) error {
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
		return nil
	})
	if err != nil {
		return Agent{}, err
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
	tokenID, err := randomID("tok_", 16)
	if err != nil {
		return IssuedToken{}, errors.New("issue agent token")
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return IssuedToken{}, errors.New("issue agent token")
	}
	raw := "owat_" + base64.RawURLEncoding.EncodeToString(entropy[:])
	clear(entropy[:])
	prefix := raw[:len("owat_")+8]
	hash := sha256.Sum256([]byte(raw))
	issued := IssuedToken{
		ID: tokenID, Prefix: prefix, Raw: raw, ExpiresAt: expiresAt,
	}
	err = service.repository.withTx(ctx, func(tx *sql.Tx) error {
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
		return nil
	})
	clear(hash[:])
	if err != nil {
		issued.Raw = ""
		return IssuedToken{}, err
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
	now := service.clock.Now().UTC()
	return service.repository.withTx(ctx, func(tx *sql.Tx) error {
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
		return nil
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
	now := service.clock.Now().UTC()
	return service.repository.withTx(ctx, func(tx *sql.Tx) error {
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
		return nil
	})
}

func (service *Service) Authenticate(
	ctx context.Context,
	raw string,
) (AuthenticatedPrincipal, error) {
	hash := sha256.Sum256([]byte(raw))
	validShape := validRawToken(raw)
	now := service.clock.Now().UTC()
	var principal AuthenticatedPrincipal
	var authErr error
	err := service.repository.withTx(ctx, func(tx *sql.Tx) error {
		tokens, err := service.repository.tokenRowsTx(ctx, tx)
		if err != nil {
			return err
		}
		match := -1
		for index := range tokens {
			equal := subtle.ConstantTimeCompare(tokens[index].Hash, hash[:])
			if equal == 1 {
				match = index
			}
		}
		if !validShape || match < 0 {
			authErr = ErrInvalidToken
			return nil
		}
		token := tokens[match]
		switch {
		case token.Prefix != raw[:len("owat_")+8]:
			authErr = ErrInvalidToken
			return nil
		case token.AgentDead:
			authErr = ErrAgentDisabled
			return nil
		case token.RevokedAt != nil:
			authErr = ErrTokenRevoked
			return nil
		case token.ExpiresAt != nil && !now.Before(*token.ExpiresAt):
			authErr = ErrTokenExpired
			return nil
		}
		grants, err := service.repository.grantsTx(ctx, tx, token.AgentID)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE agent_tokens SET last_used_at = ? WHERE id = ?
		`, formatAgentTime(now), token.ID); err != nil {
			return errors.New("authenticate agent")
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
	if authErr != nil {
		return AuthenticatedPrincipal{}, authErr
	}
	return cloneAuthenticatedPrincipal(principal), nil
}

func (service *Service) ListUsage(
	ctx context.Context,
	principal MutationContext,
) ([]Usage, error) {
	if err := validateMutationContext(principal); err != nil {
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

func validateMutationContext(principal MutationContext) error {
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
