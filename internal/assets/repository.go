package assets

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"opswarden/internal/credentials"
	"opswarden/internal/storage"
)

type Repository struct {
	db *storage.DB
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func NewRepository(db *storage.DB) (*Repository, error) {
	if db == nil || db.Writer == nil || db.Reader == nil {
		return nil, errors.New("asset database is required")
	}
	return &Repository{db: db}, nil
}

func (r *Repository) withTx(
	ctx context.Context,
	fn func(*sql.Tx) error,
) error {
	if err := storage.WithTx(ctx, r.db, fn); err != nil {
		return stableStorageError(err)
	}
	return nil
}

func (r *Repository) listBatch(
	ctx context.Context,
	filter ListFilter,
	after string,
	limit int,
) ([]Asset, error) {
	query := `
		SELECT
			id, space_id, name, type, hostname, operating_system,
			environment, status, ips_json, ports_json, notes, version,
			created_at, updated_at, deleted_at
		FROM assets
		WHERE space_id = ? AND id > ? AND deleted_at IS NULL
	`
	arguments := []any{filter.SpaceID, after}
	if filter.Type != "" {
		query += ` AND type = ?`
		arguments = append(arguments, filter.Type)
	}
	if filter.Environment != "" {
		query += ` AND environment = ?`
		arguments = append(arguments, filter.Environment)
	}
	if filter.Status != "" {
		query += ` AND status = ?`
		arguments = append(arguments, filter.Status)
	}
	tagKeys := make([]string, 0, len(filter.Tags))
	for key := range filter.Tags {
		tagKeys = append(tagKeys, key)
	}
	slices.Sort(tagKeys)
	for _, key := range tagKeys {
		encoded, err := encodeTag(key, filter.Tags[key])
		if err != nil {
			return nil, ErrInvalidInput
		}
		query += `
			AND EXISTS (
				SELECT 1 FROM asset_tags
				WHERE asset_tags.asset_id = assets.id AND asset_tags.tag = ?
			)
		`
		arguments = append(arguments, encoded)
	}
	query += ` ORDER BY id LIMIT ?`
	arguments = append(arguments, limit)
	rows, err := r.db.Reader.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	defer rows.Close()
	result := make([]Asset, 0)
	for rows.Next() {
		asset, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, asset)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate assets: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close asset rows: %w", err)
	}
	if err := loadTagsBatch(ctx, r.db.Reader, result); err != nil {
		return nil, err
	}
	return result, nil
}

func (r *Repository) byID(
	ctx context.Context,
	q queryer,
	assetID string,
) (Asset, error) {
	asset, err := scanAsset(q.QueryRowContext(ctx, `
		SELECT
			id, space_id, name, type, hostname, operating_system,
			environment, status, ips_json, ports_json, notes, version,
			created_at, updated_at, deleted_at
		FROM assets
		WHERE id = ? AND deleted_at IS NULL
	`, assetID))
	if errors.Is(err, sql.ErrNoRows) {
		return Asset{}, ErrNotFound
	}
	if err != nil {
		return Asset{}, fmt.Errorf("read asset: %w", err)
	}
	tags, err := loadTags(ctx, q, asset.ID)
	if err != nil {
		return Asset{}, err
	}
	asset.Tags = tags
	return asset, nil
}

type scanner interface {
	Scan(...any) error
}

func scanAsset(row scanner) (Asset, error) {
	var asset Asset
	var ipsJSON, portsJSON, createdAt, updatedAt string
	var deletedAt sql.NullString
	var version int64
	if err := row.Scan(
		&asset.ID, &asset.SpaceID, &asset.Name, &asset.Type,
		&asset.Hostname, &asset.OS, &asset.Environment, &asset.Status,
		&ipsJSON, &portsJSON, &asset.Notes, &version,
		&createdAt, &updatedAt, &deletedAt,
	); err != nil {
		return Asset{}, err
	}
	if version < 1 {
		return Asset{}, errors.New("invalid asset version")
	}
	asset.Version = uint64(version)
	var encodedIPs []string
	if err := json.Unmarshal([]byte(ipsJSON), &encodedIPs); err != nil {
		return Asset{}, errors.New("invalid stored asset IPs")
	}
	asset.IPs = make([]netip.Addr, len(encodedIPs))
	for index, encoded := range encodedIPs {
		address, err := netip.ParseAddr(encoded)
		if err != nil || address.Zone() != "" || address.String() != encoded {
			return Asset{}, errors.New("invalid stored asset IP")
		}
		asset.IPs[index] = address
	}
	if err := json.Unmarshal([]byte(portsJSON), &asset.Ports); err != nil {
		return Asset{}, errors.New("invalid stored asset ports")
	}
	var err error
	asset.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return Asset{}, err
	}
	asset.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return Asset{}, err
	}
	if deletedAt.Valid {
		parsed, err := parseTime(deletedAt.String)
		if err != nil {
			return Asset{}, err
		}
		asset.DeletedAt = &parsed
	}
	return asset, nil
}

func loadTags(
	ctx context.Context,
	q queryer,
	assetID string,
) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT tag FROM asset_tags WHERE asset_id = ? ORDER BY tag
	`, assetID)
	if err != nil {
		return nil, fmt.Errorf("read asset tags: %w", err)
	}
	defer rows.Close()
	tags := make(map[string]string)
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return nil, fmt.Errorf("scan asset tag: %w", err)
		}
		key, value, err := decodeTag(encoded)
		if err != nil {
			return nil, err
		}
		tags[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset tags: %w", err)
	}
	return tags, nil
}

func loadTagsBatch(
	ctx context.Context,
	q queryer,
	assets []Asset,
) error {
	if len(assets) == 0 {
		return nil
	}
	indexByID := make(map[string]int, len(assets))
	arguments := make([]any, len(assets))
	for index := range assets {
		indexByID[assets[index].ID] = index
		arguments[index] = assets[index].ID
		assets[index].Tags = make(map[string]string)
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(assets)), ",")
	rows, err := q.QueryContext(ctx, `
		SELECT asset_id, tag FROM asset_tags
		WHERE asset_id IN (`+placeholders+`)
		ORDER BY asset_id, tag
	`, arguments...)
	if err != nil {
		return fmt.Errorf("read asset tag batch: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var assetID, encoded string
		if err := rows.Scan(&assetID, &encoded); err != nil {
			return fmt.Errorf("scan asset tag batch: %w", err)
		}
		index, exists := indexByID[assetID]
		if !exists {
			return errors.New("asset tag batch contained an unknown asset")
		}
		key, value, err := decodeTag(encoded)
		if err != nil {
			return err
		}
		assets[index].Tags[key] = value
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate asset tag batch: %w", err)
	}
	return nil
}

func replaceTags(
	ctx context.Context,
	tx *sql.Tx,
	assetID string,
	tags map[string]string,
) error {
	if _, err := tx.ExecContext(
		ctx, `DELETE FROM asset_tags WHERE asset_id = ?`, assetID,
	); err != nil {
		return fmt.Errorf("delete asset tags: %w", err)
	}
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		encoded, err := encodeTag(key, tags[key])
		if err != nil {
			return ErrInvalidInput
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO asset_tags (asset_id, tag) VALUES (?, ?)
		`, assetID, encoded); err != nil {
			return fmt.Errorf("insert asset tag: %w", err)
		}
	}
	return nil
}

func (r *Repository) linkedCredentialMetadata(
	ctx context.Context,
	assetID string,
	after string,
	limit int,
) ([]credentials.Metadata, error) {
	rows, err := r.db.Reader.QueryContext(ctx, `
		SELECT c.id, c.space_id, c.name, c.type, c.current_version, c.deleted_at
		FROM asset_credentials ac
		JOIN credentials c ON c.id = ac.credential_id
		WHERE ac.asset_id = ? AND c.id > ? AND c.deleted_at IS NULL
		ORDER BY c.id
		LIMIT ?
	`, assetID, after, limit)
	if err != nil {
		return nil, fmt.Errorf("list linked credential metadata: %w", err)
	}
	defer rows.Close()
	result := make([]credentials.Metadata, 0)
	for rows.Next() {
		var metadata credentials.Metadata
		var credentialType string
		var version int64
		var deletedAt sql.NullString
		if err := rows.Scan(
			&metadata.ID, &metadata.SpaceID, &metadata.DisplayName,
			&credentialType, &version, &deletedAt,
		); err != nil {
			return nil, fmt.Errorf("scan linked credential metadata: %w", err)
		}
		if version < 1 {
			return nil, errors.New("invalid linked credential version")
		}
		metadata.Type = credentials.Type(credentialType)
		metadata.Version = uint64(version)
		metadata.Tags = make(map[string]string)
		metadata.AssetIDs = []string{assetID}
		result = append(result, metadata)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate linked credential metadata: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close linked credential metadata: %w", err)
	}
	return result, loadCredentialTagsBatch(ctx, r.db.Reader, result)
}

func loadCredentialTagsBatch(
	ctx context.Context,
	q queryer,
	metadata []credentials.Metadata,
) error {
	if len(metadata) == 0 {
		return nil
	}
	indexByID := make(map[string]int, len(metadata))
	arguments := make([]any, len(metadata))
	for index := range metadata {
		indexByID[metadata[index].ID] = index
		arguments[index] = metadata[index].ID
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(metadata)), ",")
	rows, err := q.QueryContext(ctx, `
		SELECT credential_id, tag FROM credential_tags
		WHERE credential_id IN (`+placeholders+`)
		ORDER BY credential_id, tag
	`, arguments...)
	if err != nil {
		return fmt.Errorf("read linked credential tag batch: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var credentialID, encoded string
		if err := rows.Scan(&credentialID, &encoded); err != nil {
			return fmt.Errorf("scan linked credential tag batch: %w", err)
		}
		index, exists := indexByID[credentialID]
		if !exists {
			return errors.New("credential tag batch contained an unknown credential")
		}
		key, value, err := decodeTag(encoded)
		if err != nil {
			return err
		}
		metadata[index].Tags[key] = value
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate linked credential tag batch: %w", err)
	}
	return nil
}

func encodeTag(key, value string) (string, error) {
	encoded, err := json.Marshal([2]string{key, value})
	return string(encoded), err
}

func decodeTag(encoded string) (string, string, error) {
	var pair [2]string
	if err := json.Unmarshal([]byte(encoded), &pair); err != nil {
		return "", "", errors.New("invalid stored tag")
	}
	canonical, err := json.Marshal(pair)
	if err != nil || string(canonical) != encoded {
		return "", "", errors.New("non-canonical stored tag")
	}
	return pair[0], pair[1], nil
}

const assetTimeLayout = "2006-01-02T15:04:05.000000000Z"

func formatTime(value time.Time) string {
	return value.UTC().Format(assetTimeLayout)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(assetTimeLayout, value)
	if err == nil && formatTime(parsed) == value {
		return parsed, nil
	}
	const sqliteDefaultTimeLayout = "2006-01-02 15:04:05"
	parsed, err = time.ParseInLocation(
		sqliteDefaultTimeLayout, value, time.UTC,
	)
	if err == nil && parsed.Format(sqliteDefaultTimeLayout) == value {
		return parsed, nil
	}
	return time.Time{}, errors.New("invalid stored asset time")
}
