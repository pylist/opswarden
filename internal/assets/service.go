package assets

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/credentials"
	"opswarden/internal/platform"
	"opswarden/internal/storage"
)

const (
	defaultListLimit = 100
	maxListLimit     = 500
	maxAddresses     = 128
	maxPorts         = 128
	maxTags          = 64
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
		return nil, errors.New("asset audit appender is required")
	}
	if clock == nil {
		return nil, errors.New("asset clock is required")
	}
	return &Service{
		repository: repository,
		audit:      auditAppender,
		clock:      clock,
	}, nil
}

func (s *Service) List(
	ctx context.Context,
	principal Principal,
	filter ListFilter,
) ([]Asset, error) {
	filter, err := normalizeListFilter(filter)
	if err != nil {
		return nil, err
	}
	if principal.Human != nil {
		if err := authorize(
			principal,
			authorization.Resource{SpaceID: filter.SpaceID},
			authorization.ListAsset,
		); err != nil {
			return nil, err
		}
	} else if principal.Agent != nil {
		if !agentHasSpaceScope(
			*principal.Agent, filter.SpaceID, authorization.ScopeAssetList,
		) {
			return nil, ErrNotFound
		}
	} else {
		return nil, authorization.ErrUnauthenticated
	}
	rows, err := s.repository.list(ctx, filter)
	if err != nil {
		return nil, err
	}
	result := make([]Asset, 0, len(rows))
	for _, asset := range rows {
		if err := authorize(
			principal, resourceForAsset(asset), authorization.ListAsset,
		); err != nil {
			if principal.Agent != nil && errors.Is(err, ErrNotFound) {
				continue
			}
			return nil, err
		}
		result = append(result, cloneAsset(asset))
	}
	return result, nil
}

func (s *Service) Get(
	ctx context.Context,
	principal Principal,
	assetID string,
) (Asset, error) {
	if !validIdentifier(assetID) {
		return Asset{}, ErrNotFound
	}
	asset, err := s.repository.byID(ctx, s.repository.db.Reader, assetID)
	if err != nil {
		return Asset{}, err
	}
	if err := authorize(
		principal, resourceForAsset(asset), authorization.ReadAsset,
	); err != nil {
		return Asset{}, err
	}
	return cloneAsset(asset), nil
}

func (s *Service) Create(
	ctx context.Context,
	principal Principal,
	input CreateInput,
) (Asset, error) {
	if principal.Agent != nil {
		return Asset{}, authorization.ErrDenied
	}
	input = normalizeCreateInput(input)
	if err := validateCreateInput(input); err != nil {
		return Asset{}, err
	}
	if err := authorize(
		principal,
		authorization.Resource{SpaceID: input.SpaceID, Labels: input.Tags},
		authorization.CreateAsset,
	); err != nil {
		return Asset{}, err
	}
	id, err := randomID("ast_")
	if err != nil {
		return Asset{}, err
	}
	now := s.clock.Now().UTC()
	asset := Asset{
		ID: id, SpaceID: input.SpaceID, Name: input.Name, Type: input.Type,
		Hostname: input.Hostname, OS: input.OS, Environment: input.Environment,
		Status: input.Status, IPs: input.IPs, Ports: input.Ports,
		Tags: input.Tags, Notes: input.Notes, Version: 1,
		CreatedAt: now, UpdatedAt: now,
	}
	ipsJSON, portsJSON, err := encodeNetworkMetadata(asset.IPs, asset.Ports)
	if err != nil {
		return Asset{}, ErrInvalidInput
	}
	err = s.repository.withTx(ctx, func(tx *sql.Tx) error {
		if err := requireActiveSpace(ctx, tx, asset.SpaceID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO assets (
				id, space_id, name, type, hostname, operating_system,
				environment, status, ips_json, ports_json, notes, version,
				created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, asset.ID, asset.SpaceID, asset.Name, asset.Type, asset.Hostname,
			asset.OS, asset.Environment, asset.Status, ipsJSON, portsJSON,
			asset.Notes, asset.Version, formatTime(now), formatTime(now)); err != nil {
			return fmt.Errorf("insert asset: %w", err)
		}
		if err := replaceTags(ctx, tx, asset.ID, asset.Tags); err != nil {
			return err
		}
		return s.appendAuditTx(
			ctx, tx, principal, "asset.create", asset,
			audit.ChangeFields{
				audit.FieldName, audit.FieldDescription, audit.FieldTags,
				audit.FieldVersion,
			},
		)
	})
	if err != nil {
		return Asset{}, err
	}
	return cloneAsset(asset), nil
}

func (s *Service) Update(
	ctx context.Context,
	principal Principal,
	input UpdateInput,
) (Asset, error) {
	if principal.Agent != nil {
		return Asset{}, authorization.ErrDenied
	}
	input = normalizeUpdateInput(input)
	if err := validateUpdateInput(input); err != nil {
		return Asset{}, err
	}
	var updated Asset
	err := s.repository.withTx(ctx, func(tx *sql.Tx) error {
		current, err := s.repository.byID(ctx, tx, input.AssetID)
		if err != nil {
			return err
		}
		if err := authorize(
			principal, resourceForAsset(current), authorization.UpdateAsset,
		); err != nil {
			return err
		}
		if current.Version != input.ExpectedVersion {
			return ErrVersionConflict
		}
		updated = Asset{
			ID: current.ID, SpaceID: current.SpaceID,
			Name: input.Name, Type: input.Type, Hostname: input.Hostname,
			OS: input.OS, Environment: input.Environment, Status: input.Status,
			IPs: input.IPs, Ports: input.Ports, Tags: input.Tags,
			Notes: input.Notes, Version: current.Version + 1,
			CreatedAt: current.CreatedAt, UpdatedAt: s.clock.Now().UTC(),
		}
		if err := authorize(
			principal, resourceForAsset(updated), authorization.UpdateAsset,
		); err != nil {
			return err
		}
		ipsJSON, portsJSON, err := encodeNetworkMetadata(
			updated.IPs, updated.Ports,
		)
		if err != nil {
			return ErrInvalidInput
		}
		result, err := tx.ExecContext(ctx, `
			UPDATE assets SET
				name = ?, type = ?, hostname = ?, operating_system = ?,
				environment = ?, status = ?, ips_json = ?, ports_json = ?,
				notes = ?, version = ?, updated_at = ?
			WHERE id = ? AND version = ? AND deleted_at IS NULL
		`, updated.Name, updated.Type, updated.Hostname, updated.OS,
			updated.Environment, updated.Status, ipsJSON, portsJSON,
			updated.Notes, updated.Version, formatTime(updated.UpdatedAt),
			updated.ID, input.ExpectedVersion)
		if err != nil {
			return fmt.Errorf("update asset: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("count updated assets: %w", err)
		}
		if affected != 1 {
			return ErrVersionConflict
		}
		if err := replaceTags(ctx, tx, updated.ID, updated.Tags); err != nil {
			return err
		}
		return s.appendAuditTx(
			ctx, tx, principal, "asset.update", updated,
			audit.ChangeFields{
				audit.FieldName, audit.FieldDescription, audit.FieldTags,
				audit.FieldVersion,
			},
		)
	})
	if err != nil {
		return Asset{}, err
	}
	return cloneAsset(updated), nil
}

func (s *Service) Delete(
	ctx context.Context,
	principal Principal,
	assetID string,
	expectedVersion uint64,
) error {
	if principal.Agent != nil {
		return authorization.ErrDenied
	}
	if !validIdentifier(assetID) || expectedVersion == 0 {
		return ErrInvalidInput
	}
	return s.repository.withTx(ctx, func(tx *sql.Tx) error {
		asset, err := s.repository.byID(ctx, tx, assetID)
		if err != nil {
			return err
		}
		if err := authorize(
			principal, resourceForAsset(asset), authorization.DeleteAsset,
		); err != nil {
			return err
		}
		if asset.Version != expectedVersion {
			return ErrVersionConflict
		}
		now := s.clock.Now().UTC()
		result, err := tx.ExecContext(ctx, `
			UPDATE assets
			SET deleted_at = ?, updated_at = ?, version = version + 1
			WHERE id = ? AND version = ? AND deleted_at IS NULL
		`, formatTime(now), formatTime(now), asset.ID, expectedVersion)
		if err != nil {
			return fmt.Errorf("delete asset: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("count deleted assets: %w", err)
		}
		if affected != 1 {
			return ErrVersionConflict
		}
		asset.Version++
		asset.UpdatedAt = now
		asset.DeletedAt = &now
		return s.appendAuditTx(
			ctx, tx, principal, "asset.delete", asset,
			audit.ChangeFields{audit.FieldDeletedAt, audit.FieldVersion},
		)
	})
}

func (s *Service) LinkCredential(
	ctx context.Context,
	principal Principal,
	assetID, credentialID string,
) error {
	if principal.Agent != nil {
		return authorization.ErrDenied
	}
	if !validIdentifier(assetID) || !validIdentifier(credentialID) {
		return ErrNotFound
	}
	return s.repository.withTx(ctx, func(tx *sql.Tx) error {
		asset, err := s.repository.byID(ctx, tx, assetID)
		if err != nil {
			return err
		}
		if err := authorize(
			principal, resourceForAsset(asset), authorization.LinkCredential,
		); err != nil {
			return err
		}
		credentialSpaceID, credentialTags, err := credentialIdentityTx(
			ctx, tx, credentialID,
		)
		if err != nil {
			return err
		}
		if credentialSpaceID != asset.SpaceID {
			return ErrCrossSpaceLink
		}
		if err := authorize(
			principal,
			authorization.Resource{
				SpaceID: credentialSpaceID, ResourceID: credentialID,
				Labels: credentialTags,
			},
			authorization.LinkCredential,
		); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO asset_credentials (
				space_id, asset_id, credential_id, created_at
			) VALUES (?, ?, ?, ?)
		`, asset.SpaceID, asset.ID, credentialID, formatTime(s.clock.Now().UTC()))
		if err != nil {
			return fmt.Errorf("link asset credential: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("count asset credential links: %w", err)
		}
		if affected == 0 {
			return nil
		}
		return s.appendAuditTx(
			ctx, tx, principal, "asset.credential.link", asset,
			audit.ChangeFields{audit.FieldAssetLinks},
		)
	})
}

func (s *Service) UnlinkCredential(
	ctx context.Context,
	principal Principal,
	assetID, credentialID string,
) error {
	if principal.Agent != nil {
		return authorization.ErrDenied
	}
	if !validIdentifier(assetID) || !validIdentifier(credentialID) {
		return ErrNotFound
	}
	return s.repository.withTx(ctx, func(tx *sql.Tx) error {
		asset, err := s.repository.byID(ctx, tx, assetID)
		if err != nil {
			return err
		}
		if err := authorize(
			principal, resourceForAsset(asset), authorization.LinkCredential,
		); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `
			DELETE FROM asset_credentials
			WHERE space_id = ? AND asset_id = ? AND credential_id = ?
		`, asset.SpaceID, asset.ID, credentialID)
		if err != nil {
			return fmt.Errorf("unlink asset credential: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("count removed asset credential links: %w", err)
		}
		if affected == 0 {
			return ErrNotFound
		}
		return s.appendAuditTx(
			ctx, tx, principal, "asset.credential.unlink", asset,
			audit.ChangeFields{audit.FieldAssetLinks},
		)
	})
}

func (s *Service) ListCredentialMetadata(
	ctx context.Context,
	principal Principal,
	assetID string,
) ([]credentials.Metadata, error) {
	if !validIdentifier(assetID) {
		return nil, ErrNotFound
	}
	asset, err := s.repository.byID(ctx, s.repository.db.Reader, assetID)
	if err != nil {
		return nil, err
	}
	if err := authorize(
		principal, resourceForAsset(asset), authorization.ReadAsset,
	); err != nil {
		return nil, err
	}
	rows, err := s.repository.linkedCredentialMetadata(ctx, assetID)
	if err != nil {
		return nil, err
	}
	result := make([]credentials.Metadata, 0, len(rows))
	for _, metadata := range rows {
		if err := authorize(
			principal,
			authorization.Resource{
				SpaceID: metadata.SpaceID, ResourceID: metadata.ID,
				Labels: metadata.Tags,
			},
			authorization.ListCredential,
		); err != nil {
			if principal.Agent != nil && errors.Is(err, ErrNotFound) {
				continue
			}
			return nil, err
		}
		result = append(result, cloneCredentialMetadata(metadata))
	}
	return result, nil
}

func (s *Service) appendAuditTx(
	ctx context.Context,
	tx *sql.Tx,
	principal Principal,
	action string,
	asset Asset,
	fields audit.ChangeFields,
) error {
	id, err := randomID("aud_")
	if err != nil {
		return ErrAuditUnavailable
	}
	event := audit.Event{
		ID: id, RequestID: principal.RequestID, CreatedAt: s.clock.Now().UTC(),
		Actor: principal.Actor, Action: action, SpaceID: asset.SpaceID,
		ResourceType: "asset", ResourceID: asset.ID,
		SourceIP: principal.SourceIP, UserAgent: principal.UserAgent,
		Success: true, ChangeFields: fields,
	}
	if err := s.audit.AppendTx(ctx, tx, event); err != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func credentialIdentityTx(
	ctx context.Context,
	tx *sql.Tx,
	credentialID string,
) (string, map[string]string, error) {
	var spaceID string
	err := tx.QueryRowContext(ctx, `
		SELECT space_id FROM credentials
		WHERE id = ? AND deleted_at IS NULL
	`, credentialID).Scan(&spaceID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrNotFound
	}
	if err != nil {
		return "", nil, fmt.Errorf("read credential identity: %w", err)
	}
	tags, err := loadCredentialTags(ctx, tx, credentialID)
	return spaceID, tags, err
}

func loadCredentialTags(
	ctx context.Context,
	q queryer,
	credentialID string,
) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT tag FROM credential_tags
		WHERE credential_id = ? ORDER BY tag
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
		key, value, err := decodeTag(encoded)
		if err != nil {
			return nil, err
		}
		tags[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credential tags: %w", err)
	}
	return tags, nil
}

func authorize(
	principal Principal,
	resource authorization.Resource,
	action authorization.Action,
) error {
	var decision authorization.Decision
	switch {
	case principal.Human != nil && principal.Agent == nil:
		decision = authorization.DecisionForHuman(*principal.Human, resource, action)
	case principal.Agent != nil && principal.Human == nil:
		decision = authorization.DecisionForAgent(*principal.Agent, resource, action)
	default:
		return authorization.ErrUnauthenticated
	}
	err := decision.Err()
	if errors.Is(err, authorization.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

func agentHasSpaceScope(
	principal authorization.AgentPrincipal,
	spaceID string,
	scope authorization.Scope,
) bool {
	for _, grant := range principal.Grants {
		if authorization.ValidateGrant(grant) != nil {
			continue
		}
		if grant.SpaceID != spaceID {
			continue
		}
		if _, exists := grant.Scopes[scope]; exists {
			return true
		}
	}
	return false
}

func normalizeCreateInput(input CreateInput) CreateInput {
	input.SpaceID = strings.TrimSpace(input.SpaceID)
	input.Name = strings.TrimSpace(input.Name)
	input.Type = strings.TrimSpace(input.Type)
	input.Hostname = strings.TrimSpace(input.Hostname)
	input.OS = strings.TrimSpace(input.OS)
	input.Environment = strings.TrimSpace(input.Environment)
	input.Status = strings.TrimSpace(input.Status)
	input.Notes = strings.TrimSpace(input.Notes)
	input.IPs = normalizeIPs(input.IPs)
	input.Ports = append([]uint16(nil), input.Ports...)
	slices.Sort(input.Ports)
	input.Tags = cloneTags(input.Tags)
	return input
}

func normalizeUpdateInput(input UpdateInput) UpdateInput {
	normalized := normalizeCreateInput(CreateInput{
		SpaceID: "", Name: input.Name, Type: input.Type,
		Hostname: input.Hostname, OS: input.OS, Environment: input.Environment,
		Status: input.Status, IPs: input.IPs, Ports: input.Ports,
		Tags: input.Tags, Notes: input.Notes,
	})
	input.AssetID = strings.TrimSpace(input.AssetID)
	input.Name, input.Type = normalized.Name, normalized.Type
	input.Hostname, input.OS = normalized.Hostname, normalized.OS
	input.Environment, input.Status = normalized.Environment, normalized.Status
	input.IPs, input.Ports = normalized.IPs, normalized.Ports
	input.Tags, input.Notes = normalized.Tags, normalized.Notes
	return input
}

func normalizeListFilter(filter ListFilter) (ListFilter, error) {
	filter.SpaceID = strings.TrimSpace(filter.SpaceID)
	filter.Type = strings.TrimSpace(filter.Type)
	filter.Environment = strings.TrimSpace(filter.Environment)
	filter.Status = strings.TrimSpace(filter.Status)
	filter.Tags = cloneTags(filter.Tags)
	if filter.Limit == 0 {
		filter.Limit = defaultListLimit
	}
	if !validIdentifier(filter.SpaceID) ||
		!validOptionalText(filter.Type, 128) ||
		!validOptionalText(filter.Environment, 128) ||
		!validOptionalText(filter.Status, 128) ||
		filter.Limit < 1 || filter.Limit > maxListLimit ||
		validateTags(filter.Tags) != nil {
		return ListFilter{}, ErrInvalidInput
	}
	return filter, nil
}

func validateCreateInput(input CreateInput) error {
	if !validIdentifier(input.SpaceID) {
		return ErrInvalidInput
	}
	return validateAssetFields(
		input.Name, input.Type, input.Hostname, input.OS, input.Environment,
		input.Status, input.IPs, input.Ports, input.Tags, input.Notes,
	)
}

func validateUpdateInput(input UpdateInput) error {
	if !validIdentifier(input.AssetID) || input.ExpectedVersion == 0 {
		return ErrInvalidInput
	}
	return validateAssetFields(
		input.Name, input.Type, input.Hostname, input.OS, input.Environment,
		input.Status, input.IPs, input.Ports, input.Tags, input.Notes,
	)
}

func validateAssetFields(
	name, assetType, hostname, operatingSystem, environment, status string,
	ips []netip.Addr,
	ports []uint16,
	tags map[string]string,
	notes string,
) error {
	if !validRequiredText(name, 256) ||
		!validRequiredText(assetType, 128) ||
		!validHostname(hostname) ||
		!validOptionalText(operatingSystem, 128) ||
		!validOptionalText(environment, 128) ||
		!validOptionalText(status, 128) ||
		!validOptionalText(notes, 4096) ||
		len(ips) > maxAddresses || len(ports) > maxPorts ||
		validateTags(tags) != nil {
		return ErrInvalidInput
	}
	seenIPs := make(map[netip.Addr]struct{}, len(ips))
	for _, address := range ips {
		if !address.IsValid() || address.Zone() != "" {
			return ErrInvalidInput
		}
		if _, duplicate := seenIPs[address]; duplicate {
			return ErrInvalidInput
		}
		seenIPs[address] = struct{}{}
	}
	var previous uint16
	for index, port := range ports {
		if port == 0 || (index > 0 && port == previous) {
			return ErrInvalidInput
		}
		previous = port
	}
	return nil
}

func validHostname(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 253 || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') ||
				character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validateTags(tags map[string]string) error {
	if len(tags) > maxTags {
		return ErrInvalidInput
	}
	for key, value := range tags {
		if !validRequiredText(key, 128) || !validRequiredText(value, 256) {
			return ErrInvalidInput
		}
	}
	return nil
}

func validRequiredText(value string, limit int) bool {
	return value != "" && validOptionalText(value, limit)
}

func validOptionalText(value string, limit int) bool {
	if len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character <= 0x1f || (character >= 0x7f && character <= 0x9f) {
			return false
		}
	}
	return true
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

func normalizeIPs(addresses []netip.Addr) []netip.Addr {
	cloned := append([]netip.Addr(nil), addresses...)
	slices.SortFunc(cloned, func(left, right netip.Addr) int {
		return left.Compare(right)
	})
	return cloned
}

func encodeNetworkMetadata(
	addresses []netip.Addr,
	ports []uint16,
) (string, string, error) {
	encodedAddresses := make([]string, len(addresses))
	for index, address := range addresses {
		encodedAddresses[index] = address.String()
	}
	ipsJSON, err := json.Marshal(encodedAddresses)
	if err != nil {
		return "", "", err
	}
	portsJSON, err := json.Marshal(ports)
	if err != nil {
		return "", "", err
	}
	return string(ipsJSON), string(portsJSON), nil
}

func cloneTags(tags map[string]string) map[string]string {
	cloned := make(map[string]string, len(tags))
	for key, value := range tags {
		cloned[key] = value
	}
	return cloned
}

func cloneAsset(asset Asset) Asset {
	asset.IPs = append([]netip.Addr(nil), asset.IPs...)
	asset.Ports = append([]uint16(nil), asset.Ports...)
	asset.Tags = cloneTags(asset.Tags)
	if asset.DeletedAt != nil {
		deletedAt := *asset.DeletedAt
		asset.DeletedAt = &deletedAt
	}
	return asset
}

func cloneCredentialMetadata(
	metadata credentials.Metadata,
) credentials.Metadata {
	metadata.Tags = cloneTags(metadata.Tags)
	metadata.AssetIDs = append([]string(nil), metadata.AssetIDs...)
	if metadata.DeletedAt != nil {
		deletedAt := *metadata.DeletedAt
		metadata.DeletedAt = &deletedAt
	}
	return metadata
}

func resourceForAsset(asset Asset) authorization.Resource {
	return authorization.Resource{
		SpaceID: asset.SpaceID, ResourceID: asset.ID, Labels: cloneTags(asset.Tags),
	}
}

func requireActiveSpace(
	ctx context.Context,
	tx *sql.Tx,
	spaceID string,
) error {
	var found int
	err := tx.QueryRowContext(ctx, `
		SELECT 1 FROM spaces WHERE id = ? AND deleted_at IS NULL
	`, spaceID).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("validate asset Space: %w", err)
	}
	return nil
}

func randomID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate asset ID: %w", err)
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}
