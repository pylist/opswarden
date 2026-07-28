package spaces

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"opswarden/internal/authorization"
	"opswarden/internal/identity"
	"opswarden/internal/storage"
)

type repository struct {
	db *storage.DB
}

func (r repository) withTx(
	ctx context.Context,
	fn func(*sql.Tx) error,
) error {
	return storage.WithTx(ctx, r.db, fn)
}

func (r repository) humanPrincipalTx(
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
		return authorization.HumanPrincipal{}, fmt.Errorf("read Space actor: %w", err)
	}
	principal := authorization.HumanPrincipal{
		Session:    session,
		SystemRole: systemRole,
		SpaceRoles: make(map[string]authorization.Role),
	}
	if spaceID == "" {
		return principal, nil
	}
	var role authorization.Role
	err = tx.QueryRowContext(ctx, `
		SELECT role
		FROM space_memberships
		WHERE space_id = ? AND user_id = ?
	`, spaceID, session.UserID).Scan(&role)
	if err == nil {
		principal.SpaceRoles[spaceID] = role
		return principal, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return principal, nil
	}
	return authorization.HumanPrincipal{}, fmt.Errorf("read Space actor membership: %w", err)
}

func (r repository) humanPrincipal(
	ctx context.Context,
	session identity.SessionPrincipal,
) (authorization.HumanPrincipal, error) {
	if session.UserID == "" || session.SessionID == "" {
		return authorization.HumanPrincipal{}, ErrUnauthenticated
	}
	var systemRole string
	err := r.db.Reader.QueryRowContext(ctx, `
		SELECT system_role
		FROM users
		WHERE id = ? AND deleted_at IS NULL
	`, session.UserID).Scan(&systemRole)
	if errors.Is(err, sql.ErrNoRows) {
		return authorization.HumanPrincipal{}, ErrUnauthenticated
	}
	if err != nil {
		return authorization.HumanPrincipal{}, fmt.Errorf("read Space list actor: %w", err)
	}
	return authorization.HumanPrincipal{
		Session: session, SystemRole: systemRole,
	}, nil
}

func (r repository) createTx(
	ctx context.Context,
	tx *sql.Tx,
	space Space,
	ownerUserID string,
) error {
	createdAt := formatTime(space.CreatedAt)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO spaces (id, name, created_at, updated_at)
		VALUES (?, ?, ?, ?)
	`, space.ID, space.Name, createdAt, formatTime(space.UpdatedAt)); err != nil {
		return fmt.Errorf("insert Space: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO space_memberships (space_id, user_id, role, created_at)
		VALUES (?, ?, ?, ?)
	`, space.ID, ownerUserID, Owner, createdAt); err != nil {
		return fmt.Errorf("insert Space owner: %w", err)
	}
	return nil
}

func (r repository) listForUser(
	ctx context.Context,
	userID string,
	allSpaces bool,
) ([]Space, error) {
	query := `
		SELECT s.id, s.name, m.role, s.created_at, s.updated_at
		FROM spaces s
		JOIN space_memberships m ON m.space_id = s.id
		WHERE m.user_id = ? AND s.deleted_at IS NULL
		ORDER BY lower(s.name), s.id
	`
	args := []any{userID}
	if allSpaces {
		query = `
			SELECT s.id, s.name, COALESCE(m.role, ?), s.created_at, s.updated_at
			FROM spaces s
			LEFT JOIN space_memberships m
			  ON m.space_id = s.id AND m.user_id = ?
			WHERE s.deleted_at IS NULL
			ORDER BY lower(s.name), s.id
		`
		args = []any{Owner, userID}
	}
	rows, err := r.db.Reader.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list Spaces: %w", err)
	}
	defer rows.Close()

	spaces := make([]Space, 0)
	for rows.Next() {
		var space Space
		var createdAt, updatedAt string
		if err := rows.Scan(
			&space.ID, &space.Name, &space.Role, &createdAt, &updatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan Space: %w", err)
		}
		var err error
		if space.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, err
		}
		if space.UpdatedAt, err = parseTime(updatedAt); err != nil {
			return nil, err
		}
		spaces = append(spaces, space)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Spaces: %w", err)
	}
	return spaces, nil
}

func (r repository) activeUserExistsTx(
	ctx context.Context,
	tx *sql.Tx,
	userID string,
) (bool, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM users WHERE id = ? AND deleted_at IS NULL
	`, userID).Scan(&count); err != nil {
		return false, fmt.Errorf("find Space member user: %w", err)
	}
	return count == 1, nil
}

func (r repository) membershipRoleTx(
	ctx context.Context,
	tx *sql.Tx,
	spaceID, userID string,
) (Role, error) {
	var role Role
	err := tx.QueryRowContext(ctx, `
		SELECT role FROM space_memberships
		WHERE space_id = ? AND user_id = ?
	`, spaceID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrMembershipNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read Space membership: %w", err)
	}
	return role, nil
}

func (r repository) addMembershipTx(
	ctx context.Context,
	tx *sql.Tx,
	spaceID, userID string,
	role Role,
	now time.Time,
) error {
	if _, err := r.membershipRoleTx(ctx, tx, spaceID, userID); err == nil {
		return ErrMembershipExists
	} else if !errors.Is(err, ErrMembershipNotFound) {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO space_memberships (space_id, user_id, role, created_at)
		VALUES (?, ?, ?, ?)
	`, spaceID, userID, role, formatTime(now)); err != nil {
		return fmt.Errorf("add Space membership: %w", err)
	}
	return nil
}

func (r repository) changeMembershipRoleTx(
	ctx context.Context,
	tx *sql.Tx,
	spaceID, userID string,
	role Role,
) error {
	result, err := tx.ExecContext(ctx, `
		UPDATE space_memberships SET role = ?
		WHERE space_id = ? AND user_id = ?
	`, role, spaceID, userID)
	if err != nil {
		return fmt.Errorf("change Space membership role: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read Space role change result: %w", err)
	}
	if changed != 1 {
		return ErrMembershipNotFound
	}
	return nil
}

func (r repository) removeMembershipTx(
	ctx context.Context,
	tx *sql.Tx,
	spaceID, userID string,
) error {
	result, err := tx.ExecContext(ctx, `
		DELETE FROM space_memberships WHERE space_id = ? AND user_id = ?
	`, spaceID, userID)
	if err != nil {
		return fmt.Errorf("remove Space membership: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read Space membership removal result: %w", err)
	}
	if changed != 1 {
		return ErrMembershipNotFound
	}
	return nil
}

func (r repository) remainingOwnerCountTx(
	ctx context.Context,
	tx *sql.Tx,
	spaceID, excludedUserID string,
) (int, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*)
		FROM space_memberships
		WHERE space_id = ? AND role = ? AND user_id <> ?
	`, spaceID, Owner, excludedUserID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count remaining Space Owners: %w", err)
	}
	return count, nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, errors.New("invalid Space timestamp")
	}
	return parsed, nil
}
