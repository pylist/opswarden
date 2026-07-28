package agents

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"opswarden/internal/authorization"
	"opswarden/internal/identity"
	"opswarden/internal/storage"
)

type Repository struct {
	db *storage.DB
}

type tokenRow struct {
	ID        string
	AgentID   string
	Hash      []byte
	Prefix    string
	ExpiresAt *time.Time
	RevokedAt *time.Time
	AgentDead bool
}

func NewRepository(db *storage.DB) (*Repository, error) {
	if db == nil || db.Writer == nil || db.Reader == nil {
		return nil, errors.New("agent database is required")
	}
	return &Repository{db: db}, nil
}

func (repository *Repository) withTx(
	ctx context.Context,
	fn func(*sql.Tx) error,
) error {
	return storage.WithTx(ctx, repository.db, fn)
}

func (repository *Repository) humanPrincipalTx(
	ctx context.Context,
	tx *sql.Tx,
	session identity.SessionPrincipal,
	spaceID string,
) (authorization.HumanPrincipal, error) {
	if session.UserID == "" || session.SessionID == "" {
		return authorization.HumanPrincipal{}, ErrUnauthenticated
	}
	var systemRole string
	err := tx.QueryRowContext(ctx, `
		SELECT system_role
		FROM users
		WHERE id = ? AND deleted_at IS NULL
	`, session.UserID).Scan(&systemRole)
	if errors.Is(err, sql.ErrNoRows) {
		return authorization.HumanPrincipal{}, ErrUnauthenticated
	}
	if err != nil {
		return authorization.HumanPrincipal{}, errors.New("read agent actor")
	}
	principal := authorization.HumanPrincipal{
		Session: session, SystemRole: systemRole,
		SpaceRoles: make(map[string]authorization.Role),
	}
	if spaceID == "" {
		return principal, nil
	}
	var role authorization.Role
	err = tx.QueryRowContext(ctx, `
		SELECT role FROM space_memberships
		WHERE space_id = ? AND user_id = ?
	`, spaceID, session.UserID).Scan(&role)
	if err == nil {
		principal.SpaceRoles[spaceID] = role
		return principal, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return principal, nil
	}
	return authorization.HumanPrincipal{}, errors.New("read agent actor membership")
}

func (repository *Repository) requireActiveAgentTx(
	ctx context.Context,
	tx *sql.Tx,
	agentID string,
) error {
	var active int
	err := tx.QueryRowContext(ctx, `
		SELECT 1 FROM agents WHERE id = ? AND deleted_at IS NULL
	`, agentID).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAgentNotFound
	}
	if err != nil {
		return errors.New("read agent")
	}
	return nil
}

func (repository *Repository) requireActiveSpaceTx(
	ctx context.Context,
	tx *sql.Tx,
	spaceID string,
) error {
	var active int
	err := tx.QueryRowContext(ctx, `
		SELECT 1 FROM spaces WHERE id = ? AND deleted_at IS NULL
	`, spaceID).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAgentNotFound
	}
	if err != nil {
		return errors.New("read agent grant Space")
	}
	return nil
}

func (repository *Repository) tokenRowsTx(
	ctx context.Context,
	tx *sql.Tx,
) ([]tokenRow, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT
			t.id,
			t.agent_id,
			t.token_hash,
			t.token_prefix,
			t.expires_at,
			t.revoked_at,
			a.deleted_at IS NOT NULL
		FROM agent_tokens t
		JOIN agents a ON a.id = t.agent_id
		ORDER BY t.id
	`)
	if err != nil {
		return nil, errors.New("authenticate agent")
	}
	defer rows.Close()
	var tokens []tokenRow
	for rows.Next() {
		var token tokenRow
		var expiresAt, revokedAt sql.NullString
		if err := rows.Scan(
			&token.ID, &token.AgentID, &token.Hash, &token.Prefix,
			&expiresAt, &revokedAt, &token.AgentDead,
		); err != nil {
			return nil, errors.New("authenticate agent")
		}
		var parseErr error
		if expiresAt.Valid {
			parsed, err := parseAgentTime(expiresAt.String)
			if err != nil {
				parseErr = err
			} else {
				token.ExpiresAt = &parsed
			}
		}
		if revokedAt.Valid {
			parsed, err := parseAgentTime(revokedAt.String)
			if err != nil {
				parseErr = err
			} else {
				token.RevokedAt = &parsed
			}
		}
		if parseErr != nil {
			return nil, errors.New("authenticate agent")
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("authenticate agent")
	}
	return tokens, nil
}

func (repository *Repository) grantsTx(
	ctx context.Context,
	tx *sql.Tx,
	agentID string,
) ([]Grant, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT space_id, scopes_json, labels_json
		FROM agent_space_grants
		WHERE agent_id = ?
		ORDER BY space_id
	`, agentID)
	if err != nil {
		return nil, errors.New("read agent grants")
	}
	defer rows.Close()
	var grants []Grant
	for rows.Next() {
		var grant Grant
		var scopesJSON, labelsJSON []byte
		if err := rows.Scan(&grant.SpaceID, &scopesJSON, &labelsJSON); err != nil {
			return nil, errors.New("read agent grants")
		}
		if err := decodeCanonicalJSON(scopesJSON, &grant.Scopes); err != nil {
			return nil, errors.New("read agent grants")
		}
		if err := decodeCanonicalJSON(labelsJSON, &grant.RequiredLabels); err != nil {
			return nil, errors.New("read agent grants")
		}
		normalized, err := normalizeGrant(grant)
		if err != nil ||
			!slices.Equal(normalized.Scopes, grant.Scopes) {
			return nil, errors.New("read agent grants")
		}
		grants = append(grants, normalized)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("read agent grants")
	}
	return grants, nil
}

func decodeCanonicalJSON(encoded []byte, destination any) error {
	if len(encoded) == 0 || len(encoded) > 16*1024 {
		return ErrInvalidGrant
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidGrant
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidGrant
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrInvalidGrant
	}
	return nil
}

func encodeGrant(grant Grant) ([]byte, []byte, error) {
	scopes, err := json.Marshal(grant.Scopes)
	if err != nil {
		return nil, nil, ErrInvalidGrant
	}
	labels, err := json.Marshal(grant.RequiredLabels)
	if err != nil {
		return nil, nil, ErrInvalidGrant
	}
	return scopes, labels, nil
}

func formatAgentTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

func parseAgentTime(value string) (time.Time, error) {
	parsed, err := time.Parse("2006-01-02T15:04:05.000000000Z", value)
	if err != nil || formatAgentTime(parsed) != value {
		return time.Time{}, fmt.Errorf("invalid agent time")
	}
	return parsed, nil
}
