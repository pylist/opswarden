package credentials

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"opswarden/internal/cryptobox"
	"opswarden/internal/storage"
)

type Repository struct {
	db *storage.DB
}

type credentialRecord struct {
	metadata Metadata
	envelope cryptobox.Envelope
}

type idempotencyResult struct {
	RequestHash string `json:"request_hash"`
	ResourceID  string `json:"resource_id"`
	Version     uint64 `json:"version"`
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func NewRepository(db *storage.DB) (*Repository, error) {
	if db == nil || db.Writer == nil || db.Reader == nil {
		return nil, errors.New("credential database is required")
	}
	return &Repository{db: db}, nil
}

func (r *Repository) withTx(
	ctx context.Context,
	fn func(*sql.Tx) error,
) error {
	return storage.WithTx(ctx, r.db, fn)
}

func (r *Repository) list(
	ctx context.Context,
	filter ListFilter,
) ([]Metadata, error) {
	query := `
		SELECT id, space_id, name, type, current_version, deleted_at
		FROM credentials
		WHERE space_id = ? AND id > ?
	`
	args := []any{filter.SpaceID, filter.After}
	if filter.Type != "" {
		query += ` AND type = ?`
		args = append(args, filter.Type)
	}
	switch {
	case filter.DeletedOnly:
		query += ` AND deleted_at IS NOT NULL`
	case !filter.IncludeDeleted:
		query += ` AND deleted_at IS NULL`
	}
	query += ` ORDER BY id`
	rows, err := r.db.Reader.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	defer rows.Close()

	result := make([]Metadata, 0)
	for rows.Next() {
		metadata, err := scanMetadataRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, metadata)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credentials: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close credential rows: %w", err)
	}
	filtered := make([]Metadata, 0, len(result))
	for index := range result {
		if err := r.loadRelations(ctx, r.db.Reader, &result[index]); err != nil {
			return nil, err
		}
		if labelsContain(result[index].Tags, filter.Tags) {
			filtered = append(filtered, result[index])
		}
	}
	return filtered, nil
}

func (r *Repository) recordByID(
	ctx context.Context,
	queryer queryer,
	credentialID string,
	includeDeleted bool,
) (credentialRecord, error) {
	query := `
		SELECT
			c.id, c.space_id, c.name, c.type, c.current_version, c.deleted_at,
			v.payload_ciphertext, v.payload_nonce, v.wrapped_data_key, v.wrap_nonce
		FROM credentials c
		JOIN credential_versions v
		  ON v.credential_id = c.id AND v.version = c.current_version
		WHERE c.id = ?
	`
	if !includeDeleted {
		query += ` AND c.deleted_at IS NULL`
	}
	var record credentialRecord
	var deletedAt sql.NullString
	var version int64
	var payloadNonce, wrapNonce []byte
	err := queryer.QueryRowContext(ctx, query, credentialID).Scan(
		&record.metadata.ID,
		&record.metadata.SpaceID,
		&record.metadata.DisplayName,
		&record.metadata.Type,
		&version,
		&deletedAt,
		&record.envelope.Ciphertext,
		&payloadNonce,
		&record.envelope.WrappedDataKey,
		&wrapNonce,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return credentialRecord{}, ErrNotFound
	}
	if err != nil {
		return credentialRecord{}, fmt.Errorf("read credential: %w", err)
	}
	if version < 1 || len(payloadNonce) != len(record.envelope.Nonce) ||
		len(wrapNonce) != len(record.envelope.WrapNonce) {
		return credentialRecord{}, errors.New("invalid encrypted credential record")
	}
	record.metadata.Version = uint64(version)
	copy(record.envelope.Nonce[:], payloadNonce)
	copy(record.envelope.WrapNonce[:], wrapNonce)
	if deletedAt.Valid {
		parsed, err := parseCredentialTime(deletedAt.String)
		if err != nil {
			return credentialRecord{}, err
		}
		record.metadata.DeletedAt = &parsed
	}
	if err := r.loadRelations(ctx, queryer, &record.metadata); err != nil {
		return credentialRecord{}, err
	}
	return record, nil
}

func (r *Repository) metadataByID(
	ctx context.Context,
	queryer queryer,
	credentialID string,
	includeDeleted bool,
) (Metadata, error) {
	query := `
		SELECT id, space_id, name, type, current_version, deleted_at
		FROM credentials WHERE id = ?
	`
	if !includeDeleted {
		query += ` AND deleted_at IS NULL`
	}
	metadata, err := scanMetadataRow(queryer.QueryRowContext(ctx, query, credentialID))
	if errors.Is(err, sql.ErrNoRows) {
		return Metadata{}, ErrNotFound
	}
	if err != nil {
		return Metadata{}, err
	}
	if err := r.loadRelations(ctx, queryer, &metadata); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

type scanner interface {
	Scan(...any) error
}

func scanMetadataRow(row scanner) (Metadata, error) {
	var metadata Metadata
	var version int64
	var deletedAt sql.NullString
	if err := row.Scan(
		&metadata.ID,
		&metadata.SpaceID,
		&metadata.DisplayName,
		&metadata.Type,
		&version,
		&deletedAt,
	); err != nil {
		return Metadata{}, err
	}
	if version < 1 {
		return Metadata{}, errors.New("invalid credential version")
	}
	metadata.Version = uint64(version)
	if deletedAt.Valid {
		parsed, err := parseCredentialTime(deletedAt.String)
		if err != nil {
			return Metadata{}, err
		}
		metadata.DeletedAt = &parsed
	}
	return metadata, nil
}

func (r *Repository) loadRelations(
	ctx context.Context,
	queryer queryer,
	metadata *Metadata,
) error {
	tags, err := loadTags(ctx, queryer, metadata.ID)
	if err != nil {
		return err
	}
	assetIDs, err := loadAssetIDs(ctx, queryer, metadata.ID)
	if err != nil {
		return err
	}
	metadata.Tags = tags
	metadata.AssetIDs = assetIDs
	return nil
}

func loadTags(
	ctx context.Context,
	queryer queryer,
	credentialID string,
) (map[string]string, error) {
	rows, err := queryer.QueryContext(ctx, `
		SELECT tag FROM credential_tags WHERE credential_id = ? ORDER BY tag
	`, credentialID)
	if err != nil {
		return nil, fmt.Errorf("read credential tags: %w", err)
	}
	defer rows.Close()
	tags := make(map[string]string)
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return nil, fmt.Errorf("scan credential tag: %w", err)
		}
		var pair [2]string
		if err := json.Unmarshal([]byte(encoded), &pair); err != nil || pair[0] == "" {
			return nil, errors.New("invalid stored credential tag")
		}
		tags[pair[0]] = pair[1]
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credential tags: %w", err)
	}
	return tags, nil
}

func loadAssetIDs(
	ctx context.Context,
	queryer queryer,
	credentialID string,
) ([]string, error) {
	rows, err := queryer.QueryContext(ctx, `
		SELECT asset_id FROM asset_credentials
		WHERE credential_id = ? ORDER BY asset_id
	`, credentialID)
	if err != nil {
		return nil, fmt.Errorf("read credential assets: %w", err)
	}
	defer rows.Close()
	assetIDs := make([]string, 0)
	for rows.Next() {
		var assetID string
		if err := rows.Scan(&assetID); err != nil {
			return nil, fmt.Errorf("scan credential asset: %w", err)
		}
		assetIDs = append(assetIDs, assetID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credential assets: %w", err)
	}
	return assetIDs, nil
}

func replaceTags(
	ctx context.Context,
	tx *sql.Tx,
	credentialID string,
	tags map[string]string,
) error {
	if _, err := tx.ExecContext(
		ctx, `DELETE FROM credential_tags WHERE credential_id = ?`, credentialID,
	); err != nil {
		return fmt.Errorf("delete credential tags: %w", err)
	}
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		encoded, err := json.Marshal([2]string{key, tags[key]})
		if err != nil {
			return ErrInvalidInput
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO credential_tags (credential_id, tag) VALUES (?, ?)
		`, credentialID, string(encoded)); err != nil {
			return fmt.Errorf("insert credential tag: %w", err)
		}
	}
	return nil
}

func replaceAssetLinks(
	ctx context.Context,
	tx *sql.Tx,
	credentialID, spaceID string,
	assetIDs []string,
	now time.Time,
) error {
	if _, err := tx.ExecContext(
		ctx, `DELETE FROM asset_credentials WHERE credential_id = ?`, credentialID,
	); err != nil {
		return fmt.Errorf("delete credential asset links: %w", err)
	}
	for _, assetID := range assetIDs {
		var found int
		err := tx.QueryRowContext(ctx, `
			SELECT 1 FROM assets
			WHERE id = ? AND space_id = ? AND deleted_at IS NULL
		`, assetID, spaceID).Scan(&found)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("validate credential asset: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO asset_credentials (
				space_id, asset_id, credential_id, created_at
			) VALUES (?, ?, ?, ?)
		`, spaceID, assetID, credentialID, formatCredentialTime(now)); err != nil {
			return fmt.Errorf("insert credential asset link: %w", err)
		}
	}
	return nil
}

func lookupIdempotency(
	ctx context.Context,
	tx *sql.Tx,
	agentID, endpoint string,
	keyHash []byte,
	now time.Time,
) (idempotencyResult, bool, error) {
	var encoded []byte
	var expiresAt string
	err := tx.QueryRowContext(ctx, `
		SELECT response_headers, expires_at
		FROM idempotency_records
		WHERE agent_id = ? AND endpoint = ? AND key_hash = ?
	`, agentID, endpoint, keyHash).Scan(&encoded, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return idempotencyResult{}, false, nil
	}
	if err != nil {
		return idempotencyResult{}, false, fmt.Errorf("read idempotency result: %w", err)
	}
	expiry, err := parseCredentialTime(expiresAt)
	if err != nil {
		return idempotencyResult{}, false, err
	}
	if !expiry.After(now) {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM idempotency_records
			WHERE agent_id = ? AND endpoint = ? AND key_hash = ?
		`, agentID, endpoint, keyHash); err != nil {
			return idempotencyResult{}, false, fmt.Errorf("expire idempotency result: %w", err)
		}
		return idempotencyResult{}, false, nil
	}
	var result idempotencyResult
	if err := json.Unmarshal(encoded, &result); err != nil ||
		result.RequestHash == "" || result.ResourceID == "" {
		return idempotencyResult{}, false, errors.New("invalid idempotency result")
	}
	return result, true, nil
}

func storeIdempotency(
	ctx context.Context,
	tx *sql.Tx,
	id, agentID, endpoint string,
	keyHash []byte,
	status int,
	result idempotencyResult,
	now time.Time,
) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		return errors.New("encode idempotency result")
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO idempotency_records (
			id, agent_id, endpoint, key_hash, response_status,
			response_headers, response_body, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)
	`, id, agentID, endpoint, keyHash, status, encoded,
		formatCredentialTime(now), formatCredentialTime(now.Add(24*time.Hour)))
	if err != nil {
		return fmt.Errorf("store idempotency result: %w", err)
	}
	return nil
}

func labelsContain(actual, required map[string]string) bool {
	for key, value := range required {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func formatCredentialTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseCredentialTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || formatCredentialTime(parsed) != value {
		return time.Time{}, errors.New("invalid credential timestamp")
	}
	return parsed, nil
}
