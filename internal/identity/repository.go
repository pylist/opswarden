package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"opswarden/internal/storage"
)

type repository struct {
	db *storage.DB
}

type userRecord struct {
	ID           string
	PasswordHash []byte
}

type recoveryCodeRecord struct {
	ID   string
	Hash []byte
}

type sessionRecord struct {
	ID            string
	UserID        string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	IdleExpiresAt time.Time
	Revoked       bool
	RecentTOTPAt  time.Time
}

func (r *repository) findUserByNormalizedEmail(ctx context.Context, email string) (userRecord, error) {
	var record userRecord
	err := r.db.Reader.QueryRowContext(ctx, `
		SELECT id, password_hash
		FROM users
		WHERE normalized_email = ? AND deleted_at IS NULL
	`, email).Scan(&record.ID, &record.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return userRecord{}, ErrUserNotFound
	}
	if err != nil {
		return userRecord{}, fmt.Errorf("find identity user: %w", err)
	}
	return record, nil
}

func (r *repository) createInitialOwner(
	ctx context.Context,
	userID, email, normalizedEmail string,
	passwordHash, encryptedTOTP []byte,
	recoveryCodes []recoveryCodeRecord,
	now time.Time,
) error {
	return storage.WithTx(ctx, r.db, func(tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&count); err != nil {
			return fmt.Errorf("count identity users: %w", err)
		}
		if count != 0 {
			return ErrInitialOwnerExists
		}
		timestamp := formatTime(now)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO users
				(id, email, normalized_email, password_hash, system_role, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, userID, email, normalizedEmail, passwordHash, SystemRoleOwner, timestamp, timestamp); err != nil {
			return fmt.Errorf("insert initial owner: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO user_totp (user_id, encrypted_secret, created_at, updated_at)
			VALUES (?, ?, ?, ?)
		`, userID, encryptedTOTP, timestamp, timestamp); err != nil {
			return fmt.Errorf("insert owner TOTP: %w", err)
		}
		for _, code := range recoveryCodes {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO recovery_codes (id, user_id, code_hash, created_at)
				VALUES (?, ?, ?, ?)
			`, code.ID, userID, code.Hash, timestamp); err != nil {
				return fmt.Errorf("insert recovery code: %w", err)
			}
		}
		return nil
	})
}

func (r *repository) completeLogin(
	ctx context.Context,
	userID string,
	expectedPasswordHash []byte,
	now time.Time,
	verify func(*sql.Tx, []byte, sql.NullInt64) error,
	sessionID string,
	tokenHash []byte,
	expiresAt, idleExpiresAt time.Time,
	recentTOTP bool,
	upgradedPasswordHash []byte,
) error {
	return storage.WithTx(ctx, r.db, func(tx *sql.Tx) error {
		var currentPasswordHash []byte
		if err := tx.QueryRowContext(ctx, `
			SELECT password_hash FROM users WHERE id = ? AND deleted_at IS NULL
		`, userID).Scan(&currentPasswordHash); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrInvalidChallenge
			}
			return fmt.Errorf("read challenged identity user: %w", err)
		}
		if !bytes.Equal(currentPasswordHash, expectedPasswordHash) {
			return ErrInvalidChallenge
		}
		var encryptedSecret []byte
		var lastCounter sql.NullInt64
		if err := tx.QueryRowContext(ctx, `
			SELECT encrypted_secret, last_used_counter
			FROM user_totp
			WHERE user_id = ?
		`, userID).Scan(&encryptedSecret, &lastCounter); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrInvalidCredentials
			}
			return fmt.Errorf("read login second factor: %w", err)
		}
		if err := verify(tx, encryptedSecret, lastCounter); err != nil {
			return err
		}
		if len(upgradedPasswordHash) != 0 {
			if _, err := tx.ExecContext(ctx, `
				UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?
			`, upgradedPasswordHash, formatTime(now), userID); err != nil {
				return fmt.Errorf("upgrade password hash: %w", err)
			}
		}
		var recentTOTPAt any
		if recentTOTP {
			recentTOTPAt = formatTime(now)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sessions
				(id, user_id, token_hash, created_at, expires_at, idle_expires_at, recent_totp_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, sessionID, userID, tokenHash, formatTime(now), formatTime(expiresAt),
			formatTime(idleExpiresAt), recentTOTPAt); err != nil {
			return fmt.Errorf("create identity session: %w", err)
		}
		return nil
	})
}

func consumeTOTPCounter(
	ctx context.Context,
	tx *sql.Tx,
	userID string,
	counter int64,
	now time.Time,
) error {
	result, err := tx.ExecContext(ctx, `
		UPDATE user_totp
		SET last_used_counter = ?, updated_at = ?
		WHERE user_id = ?
		  AND (last_used_counter IS NULL OR last_used_counter < ?)
	`, counter, formatTime(now), userID, counter)
	if err != nil {
		return fmt.Errorf("consume TOTP counter: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read TOTP consumption result: %w", err)
	}
	if changed != 1 {
		return ErrTOTPReplay
	}
	return nil
}

func consumeRecoveryCode(
	ctx context.Context,
	tx *sql.Tx,
	userID string,
	codeHash []byte,
	now time.Time,
) error {
	result, err := tx.ExecContext(ctx, `
		UPDATE recovery_codes
		SET used_at = ?
		WHERE user_id = ? AND code_hash = ? AND used_at IS NULL
	`, formatTime(now), userID, codeHash)
	if err != nil {
		return fmt.Errorf("consume recovery code: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read recovery code consumption result: %w", err)
	}
	if changed != 1 {
		return ErrInvalidRecoveryCode
	}
	return nil
}

func (r *repository) resolveSession(
	ctx context.Context,
	rawToken string,
	now time.Time,
) (SessionPrincipal, error) {
	tokenHash := sha256.Sum256([]byte(rawToken))
	var principal SessionPrincipal
	err := storage.WithTx(ctx, r.db, func(tx *sql.Tx) error {
		record, err := querySession(ctx, tx, tokenHash[:])
		if err != nil {
			return err
		}
		if record.Revoked {
			return ErrSessionRevoked
		}
		if !now.Before(record.ExpiresAt) || !now.Before(record.IdleExpiresAt) {
			return ErrSessionExpired
		}
		nextIdle := now.Add(SessionIdleLifetime)
		if nextIdle.After(record.ExpiresAt) {
			nextIdle = record.ExpiresAt
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE sessions SET idle_expires_at = ? WHERE id = ?`,
			formatTime(nextIdle), record.ID,
		); err != nil {
			return fmt.Errorf("refresh session idle expiry: %w", err)
		}
		principal = principalFromSession(record)
		return nil
	})
	return principal, err
}

func (r *repository) verifyRecentTOTP(
	ctx context.Context,
	rawToken string,
	now time.Time,
	verify func(*sql.Tx, string, []byte, sql.NullInt64) error,
) (SessionPrincipal, error) {
	tokenHash := sha256.Sum256([]byte(rawToken))
	var principal SessionPrincipal
	err := storage.WithTx(ctx, r.db, func(tx *sql.Tx) error {
		record, err := querySession(ctx, tx, tokenHash[:])
		if err != nil {
			return err
		}
		if record.Revoked {
			return ErrSessionRevoked
		}
		if !now.Before(record.ExpiresAt) || !now.Before(record.IdleExpiresAt) {
			return ErrSessionExpired
		}
		var encryptedSecret []byte
		var lastCounter sql.NullInt64
		if err := tx.QueryRowContext(ctx, `
			SELECT encrypted_secret, last_used_counter FROM user_totp WHERE user_id = ?
		`, record.UserID).Scan(&encryptedSecret, &lastCounter); err != nil {
			return fmt.Errorf("read recent TOTP state: %w", err)
		}
		if err := verify(tx, record.UserID, encryptedSecret, lastCounter); err != nil {
			return err
		}
		nextIdle := now.Add(SessionIdleLifetime)
		if nextIdle.After(record.ExpiresAt) {
			nextIdle = record.ExpiresAt
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE sessions SET recent_totp_at = ?, idle_expires_at = ? WHERE id = ?
		`, formatTime(now), formatTime(nextIdle), record.ID); err != nil {
			return fmt.Errorf("record recent TOTP: %w", err)
		}
		record.RecentTOTPAt = now
		principal = principalFromSession(record)
		return nil
	})
	return principal, err
}

func querySession(ctx context.Context, tx *sql.Tx, tokenHash []byte) (sessionRecord, error) {
	var record sessionRecord
	var createdAt, expiresAt, idleExpiresAt string
	var revokedAt, recentTOTPAt sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT id, user_id, created_at, expires_at, idle_expires_at, revoked_at, recent_totp_at
		FROM sessions WHERE token_hash = ?
	`, tokenHash).Scan(
		&record.ID, &record.UserID, &createdAt, &expiresAt, &idleExpiresAt,
		&revokedAt, &recentTOTPAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return sessionRecord{}, ErrInvalidSession
	}
	if err != nil {
		return sessionRecord{}, fmt.Errorf("read identity session: %w", err)
	}
	record.Revoked = revokedAt.Valid
	var parseErr error
	if record.CreatedAt, parseErr = parseTime(createdAt); parseErr != nil {
		return sessionRecord{}, parseErr
	}
	if record.ExpiresAt, parseErr = parseTime(expiresAt); parseErr != nil {
		return sessionRecord{}, parseErr
	}
	if record.IdleExpiresAt, parseErr = parseTime(idleExpiresAt); parseErr != nil {
		return sessionRecord{}, parseErr
	}
	if recentTOTPAt.Valid {
		if record.RecentTOTPAt, parseErr = parseTime(recentTOTPAt.String); parseErr != nil {
			return sessionRecord{}, parseErr
		}
	}
	return record, nil
}

func (r *repository) revokeSession(ctx context.Context, rawToken string, now time.Time) error {
	tokenHash := sha256.Sum256([]byte(rawToken))
	return storage.WithTx(ctx, r.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE token_hash = ?
		`, formatTime(now), tokenHash[:])
		if err != nil {
			return fmt.Errorf("revoke identity session: %w", err)
		}
		return nil
	})
}

func (r *repository) revokeUserSessions(ctx context.Context, userID string, now time.Time) error {
	return storage.WithTx(ctx, r.db, func(tx *sql.Tx) error {
		return revokeUserSessionsTx(ctx, tx, userID, now)
	})
}

func (r *repository) changeSystemRole(
	ctx context.Context,
	actorUserID, targetUserID, role string,
	now time.Time,
) error {
	return storage.WithTx(ctx, r.db, func(tx *sql.Tx) error {
		var actorRole string
		if err := tx.QueryRowContext(ctx, `
			SELECT system_role FROM users WHERE id = ? AND deleted_at IS NULL
		`, actorUserID).Scan(&actorRole); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrForbidden
			}
			return fmt.Errorf("read system-role actor: %w", err)
		}
		if actorRole != SystemRoleOwner {
			return ErrForbidden
		}
		result, err := tx.ExecContext(ctx, `
			UPDATE users SET system_role = ?, updated_at = ?
			WHERE id = ? AND deleted_at IS NULL
		`, role, formatTime(now), targetUserID)
		if err != nil {
			return fmt.Errorf("change system role: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("read system-role change result: %w", err)
		}
		if changed != 1 {
			return ErrUserNotFound
		}
		return revokeUserSessionsTx(ctx, tx, targetUserID, now)
	})
}

func revokeUserSessionsTx(ctx context.Context, tx *sql.Tx, userID string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE user_id = ?
	`, formatTime(now), userID); err != nil {
		return fmt.Errorf("revoke user sessions: %w", err)
	}
	return nil
}

func (r *repository) resetPassword(
	ctx context.Context,
	userID string,
	passwordHash []byte,
	now time.Time,
) error {
	return storage.WithTx(ctx, r.db, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `
			UPDATE users SET password_hash = ?, updated_at = ?
			WHERE id = ? AND deleted_at IS NULL
		`, passwordHash, formatTime(now), userID)
		if err != nil {
			return fmt.Errorf("reset identity password: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("read password reset result: %w", err)
		}
		if changed != 1 {
			return ErrUserNotFound
		}
		return revokeUserSessionsTx(ctx, tx, userID, now)
	})
}

func principalFromSession(record sessionRecord) SessionPrincipal {
	return SessionPrincipal{
		UserID:       record.UserID,
		SessionID:    record.ID,
		IssuedAt:     record.CreatedAt,
		RecentTOTPAt: record.RecentTOTPAt,
	}
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, errors.New("invalid identity timestamp")
	}
	return parsed, nil
}
