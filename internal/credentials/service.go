package credentials

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/cryptobox"
	"opswarden/internal/platform"
	"opswarden/internal/storage"
)

const (
	defaultListLimit = 100
	maxListLimit     = 500
	recycleRetention = 30 * 24 * time.Hour
)

type AuditAppender interface {
	AppendTx(context.Context, *sql.Tx, audit.Event) error
}

type Service struct {
	repository *Repository
	box        *cryptobox.Box
	audit      AuditAppender
	clock      platform.Clock
}

func NewService(
	db *storage.DB,
	box *cryptobox.Box,
	auditAppender AuditAppender,
	clock platform.Clock,
) (*Service, error) {
	repository, err := NewRepository(db)
	if err != nil {
		return nil, err
	}
	if box == nil {
		return nil, errors.New("credential cryptobox is required")
	}
	if auditAppender == nil {
		return nil, errors.New("credential audit appender is required")
	}
	if clock == nil {
		return nil, errors.New("credential clock is required")
	}
	return &Service{
		repository: repository,
		box:        box,
		audit:      auditAppender,
		clock:      clock,
	}, nil
}

func (s *Service) List(
	ctx context.Context,
	principal Principal,
	filter ListFilter,
) ([]Metadata, string, error) {
	limit, err := validateListFilter(filter)
	if err != nil {
		return nil, "", err
	}
	if principal.Human != nil {
		if err := authorize(
			principal,
			authorization.Resource{SpaceID: filter.SpaceID},
			authorization.ListCredential,
		); err != nil {
			return nil, "", err
		}
	} else if principal.Agent != nil {
		allowed := false
		for _, grant := range principal.Agent.Grants {
			if grant.SpaceID != filter.SpaceID {
				continue
			}
			err := authorize(
				principal,
				authorization.Resource{
					SpaceID: filter.SpaceID, Labels: cloneTags(grant.Labels),
				},
				authorization.ListCredential,
			)
			if err == nil {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, "", ErrNotFound
		}
	} else {
		return nil, "", authorization.ErrUnauthenticated
	}
	rows, err := s.repository.list(ctx, filter)
	if err != nil {
		return nil, "", err
	}
	authorized := make([]Metadata, 0, min(len(rows), limit+1))
	for _, metadata := range rows {
		if err := authorize(
			principal,
			resourceForMetadata(metadata),
			authorization.ListCredential,
		); err != nil {
			if principal.Agent != nil && errors.Is(err, ErrNotFound) {
				continue
			}
			return nil, "", err
		}
		authorized = append(authorized, metadata)
		if len(authorized) == limit+1 {
			break
		}
	}
	if len(authorized) <= limit {
		return authorized, "", nil
	}
	next := authorized[limit-1].ID
	return authorized[:limit], next, nil
}

func (s *Service) Get(
	ctx context.Context,
	principal Principal,
	credentialID string,
) (Decrypted, error) {
	if credentialID == "" {
		return Decrypted{}, ErrNotFound
	}
	record, err := s.repository.recordByID(
		ctx, s.repository.db.Reader, credentialID, false,
	)
	if err != nil {
		return Decrypted{}, err
	}
	if err := authorize(
		principal, resourceForMetadata(record.metadata), authorization.ReadCredential,
	); err != nil {
		return Decrypted{}, err
	}
	plaintext, err := s.box.DecryptCredential(
		cryptobox.CredentialContext{
			CredentialID: record.metadata.ID,
			SpaceID:      record.metadata.SpaceID,
			Version:      record.metadata.Version,
			Type:         string(record.metadata.Type),
		},
		record.envelope,
	)
	if err != nil {
		return Decrypted{}, errors.New("decrypt credential")
	}
	defer clearBytes(plaintext)

	event, err := s.auditEvent(
		principal, audit.Actor{}, "credential.read", record.metadata,
		nil, "",
	)
	if err != nil {
		return Decrypted{}, ErrAuditUnavailable
	}
	if err := s.repository.withTx(ctx, func(tx *sql.Tx) error {
		return s.audit.AppendTx(ctx, tx, event)
	}); err != nil {
		return Decrypted{}, ErrAuditUnavailable
	}

	return Decrypted{
		Metadata: cloneMetadata(record.metadata),
		Payload:  json.RawMessage(bytes.Clone(plaintext)),
	}, nil
}

func (s *Service) Create(
	ctx context.Context,
	principal Principal,
	input CreateInput,
	writeContext WriteContext,
) (Metadata, error) {
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if err := validateCreateInput(input); err != nil {
		return Metadata{}, err
	}
	if err := validateMutationContext(principal, writeContext); err != nil {
		return Metadata{}, err
	}
	canonicalPayload, err := ValidatePayload(input.Type, input.Payload)
	if err != nil {
		return Metadata{}, err
	}
	defer clearBytes(canonicalPayload)
	input.Tags = cloneTags(input.Tags)
	input.AssetIDs = normalizedAssetIDs(input.AssetIDs)
	if err := authorize(
		principal,
		authorization.Resource{SpaceID: input.SpaceID, Labels: input.Tags},
		authorization.CreateCredential,
	); err != nil {
		return Metadata{}, err
	}
	id, err := randomCredentialID("crd_")
	if err != nil {
		return Metadata{}, err
	}
	metadata := Metadata{
		ID: id, SpaceID: input.SpaceID, DisplayName: input.DisplayName,
		Type: input.Type, Version: 1, Tags: input.Tags, AssetIDs: input.AssetIDs,
	}
	envelope, err := s.box.EncryptCredential(
		cryptobox.CredentialContext{
			CredentialID: metadata.ID,
			SpaceID:      metadata.SpaceID,
			Version:      metadata.Version,
			Type:         string(metadata.Type),
		},
		canonicalPayload,
	)
	if err != nil {
		return Metadata{}, errors.New("encrypt credential")
	}
	requestHash, err := requestFingerprint(struct {
		Operation string          `json:"operation"`
		Input     CreateInput     `json:"input"`
		Payload   json.RawMessage `json:"payload"`
	}{Operation: "create", Input: inputWithoutPayload(input), Payload: canonicalPayload})
	if err != nil {
		return Metadata{}, err
	}
	now := s.clock.Now().UTC()
	var replayed *idempotencyResult
	err = s.repository.withTx(ctx, func(tx *sql.Tx) error {
		replay, err := s.checkIdempotency(
			ctx, tx, principal, writeContext, "credential.create", requestHash, now,
		)
		if err != nil {
			return err
		}
		if replay != nil {
			replayed = replay
			return nil
		}
		if err := requireActiveSpace(ctx, tx, metadata.SpaceID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO credentials (
				id, space_id, name, type, current_version, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?)
		`, metadata.ID, metadata.SpaceID, metadata.DisplayName, metadata.Type,
			metadata.Version, formatCredentialTime(now), formatCredentialTime(now)); err != nil {
			return fmt.Errorf("insert credential: %w", err)
		}
		if err := insertVersion(
			ctx, tx, metadata, envelope, principal, now,
		); err != nil {
			return err
		}
		if err := replaceTags(ctx, tx, metadata.ID, metadata.Tags); err != nil {
			return err
		}
		if err := replaceAssetLinks(
			ctx, tx, metadata.ID, metadata.SpaceID, metadata.AssetIDs, now,
		); err != nil {
			return err
		}
		event, err := s.auditEvent(
			principal, writeContext.Actor, "credential.create", metadata,
			audit.ChangeFields{
				audit.FieldDisplayName, audit.FieldCredentialType, audit.FieldTags,
				audit.FieldAssetLinks, audit.FieldVersion,
			},
			writeContext.Reason,
		)
		if err != nil {
			return ErrAuditUnavailable
		}
		if err := s.audit.AppendTx(ctx, tx, event); err != nil {
			return ErrAuditUnavailable
		}
		return s.saveIdempotency(
			ctx, tx, principal, writeContext, "credential.create", requestHash,
			metadata.ID, metadata.Version, 201, now,
		)
	})
	if err != nil {
		return Metadata{}, err
	}
	if replayed != nil {
		replayedMetadata, err := s.repository.metadataByID(
			ctx, s.repository.db.Reader, replayed.ResourceID, true,
		)
		if err != nil {
			return Metadata{}, err
		}
		replayedMetadata.Version = replayed.Version
		return replayedMetadata, nil
	}
	return cloneMetadata(metadata), nil
}

func (s *Service) Update(
	ctx context.Context,
	principal Principal,
	input UpdateInput,
	writeContext WriteContext,
) (Metadata, error) {
	if input.ExpectedVersion == 0 {
		return Metadata{}, ErrVersionConflict
	}
	if input.CredentialID == "" ||
		(input.DisplayName == nil && input.Tags == nil &&
			input.AssetIDs == nil && input.Payload == nil) {
		return Metadata{}, ErrInvalidInput
	}
	if err := validateMutationContext(principal, writeContext); err != nil {
		return Metadata{}, err
	}
	requestHash, err := requestFingerprint(struct {
		Operation string      `json:"operation"`
		Input     UpdateInput `json:"input"`
	}{Operation: "update", Input: input})
	if err != nil {
		return Metadata{}, err
	}
	now := s.clock.Now().UTC()
	current, err := s.repository.recordByID(
		ctx, s.repository.db.Reader, input.CredentialID, true,
	)
	if err != nil {
		return Metadata{}, err
	}
	if err := authorize(
		principal, resourceForMetadata(current.metadata), authorization.UpdateCredential,
	); err != nil {
		return Metadata{}, err
	}
	if principal.Agent != nil {
		var replayed *idempotencyResult
		err := s.repository.withTx(ctx, func(tx *sql.Tx) error {
			var err error
			replayed, err = s.checkIdempotency(
				ctx, tx, principal, writeContext,
				"credential.update/"+input.CredentialID, requestHash, now,
			)
			return err
		})
		if err != nil {
			return Metadata{}, err
		}
		if replayed != nil {
			metadata := cloneMetadata(current.metadata)
			metadata.Version = replayed.Version
			return metadata, nil
		}
	}
	if current.metadata.DeletedAt != nil {
		return Metadata{}, ErrNotFound
	}
	if current.metadata.Version != input.ExpectedVersion {
		return Metadata{}, ErrVersionConflict
	}
	updated := cloneMetadata(current.metadata)
	updated.Version++
	changeFields := audit.ChangeFields{audit.FieldVersion}
	if input.DisplayName != nil {
		name := strings.TrimSpace(*input.DisplayName)
		if !validText(name, 256, false) {
			return Metadata{}, ErrInvalidInput
		}
		updated.DisplayName = name
		changeFields = append(changeFields, audit.FieldDisplayName)
	}
	if input.Tags != nil {
		if err := validateTags(input.Tags); err != nil {
			return Metadata{}, err
		}
		updated.Tags = cloneTags(input.Tags)
		changeFields = append(changeFields, audit.FieldTags)
	}
	if input.AssetIDs != nil {
		if err := validateAssetIDs(input.AssetIDs); err != nil {
			return Metadata{}, err
		}
		updated.AssetIDs = normalizedAssetIDs(input.AssetIDs)
		changeFields = append(changeFields, audit.FieldAssetLinks)
	}
	if err := authorize(
		principal, resourceForMetadata(updated), authorization.UpdateCredential,
	); err != nil {
		return Metadata{}, err
	}
	var plaintext []byte
	if input.Payload != nil {
		plaintext, err = ValidatePayload(current.metadata.Type, input.Payload)
	} else {
		plaintext, err = s.box.DecryptCredential(
			cryptobox.CredentialContext{
				CredentialID: current.metadata.ID,
				SpaceID:      current.metadata.SpaceID,
				Version:      current.metadata.Version,
				Type:         string(current.metadata.Type),
			},
			current.envelope,
		)
	}
	if err != nil {
		if errors.Is(err, ErrInvalidPayload) {
			return Metadata{}, err
		}
		return Metadata{}, errors.New("prepare credential version")
	}
	defer clearBytes(plaintext)
	envelope, err := s.box.EncryptCredential(
		cryptobox.CredentialContext{
			CredentialID: updated.ID, SpaceID: updated.SpaceID,
			Version: updated.Version, Type: string(updated.Type),
		},
		plaintext,
	)
	if err != nil {
		return Metadata{}, errors.New("encrypt credential")
	}
	var replayed *idempotencyResult
	err = s.repository.withTx(ctx, func(tx *sql.Tx) error {
		endpoint := "credential.update/" + input.CredentialID
		replay, err := s.checkIdempotency(
			ctx, tx, principal, writeContext, endpoint, requestHash, now,
		)
		if err != nil {
			return err
		}
		if replay != nil {
			replayed = replay
			return nil
		}
		result, err := tx.ExecContext(ctx, `
			UPDATE credentials
			SET name = ?, current_version = ?, updated_at = ?
			WHERE id = ? AND current_version = ? AND deleted_at IS NULL
		`, updated.DisplayName, updated.Version, formatCredentialTime(now),
			updated.ID, input.ExpectedVersion)
		if err != nil {
			return fmt.Errorf("update credential: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("count credential update: %w", err)
		}
		if affected != 1 {
			return ErrVersionConflict
		}
		if err := insertVersion(ctx, tx, updated, envelope, principal, now); err != nil {
			return err
		}
		if input.Tags != nil {
			if err := replaceTags(ctx, tx, updated.ID, updated.Tags); err != nil {
				return err
			}
		}
		if input.AssetIDs != nil {
			if err := replaceAssetLinks(
				ctx, tx, updated.ID, updated.SpaceID, updated.AssetIDs, now,
			); err != nil {
				return err
			}
		}
		event, err := s.auditEvent(
			principal, writeContext.Actor, "credential.update", updated,
			changeFields, writeContext.Reason,
		)
		if err != nil {
			return ErrAuditUnavailable
		}
		if err := s.audit.AppendTx(ctx, tx, event); err != nil {
			return ErrAuditUnavailable
		}
		return s.saveIdempotency(
			ctx, tx, principal, writeContext, endpoint, requestHash,
			updated.ID, updated.Version, 200, now,
		)
	})
	if err != nil {
		return Metadata{}, err
	}
	if replayed != nil {
		metadata, err := s.repository.metadataByID(
			ctx, s.repository.db.Reader, replayed.ResourceID, true,
		)
		if err != nil {
			return Metadata{}, err
		}
		metadata.Version = replayed.Version
		return metadata, nil
	}
	return cloneMetadata(updated), nil
}

func (s *Service) Delete(
	ctx context.Context,
	principal Principal,
	credentialID string,
	expectedVersion uint64,
	writeContext WriteContext,
) error {
	if expectedVersion == 0 {
		return ErrVersionConflict
	}
	if credentialID == "" {
		return ErrNotFound
	}
	if err := validateMutationContext(principal, writeContext); err != nil {
		return err
	}
	requestHash, err := requestFingerprint(struct {
		Operation       string `json:"operation"`
		CredentialID    string `json:"credential_id"`
		ExpectedVersion uint64 `json:"expected_version"`
	}{Operation: "delete", CredentialID: credentialID, ExpectedVersion: expectedVersion})
	if err != nil {
		return err
	}
	now := s.clock.Now().UTC()
	return s.repository.withTx(ctx, func(tx *sql.Tx) error {
		endpoint := "credential.delete/" + credentialID
		metadata, err := s.repository.metadataByID(ctx, tx, credentialID, true)
		if err != nil {
			return err
		}
		if err := authorize(
			principal, resourceForMetadata(metadata), authorization.DeleteCredential,
		); err != nil {
			return err
		}
		replay, err := s.checkIdempotency(
			ctx, tx, principal, writeContext, endpoint, requestHash, now,
		)
		if err != nil || replay != nil {
			return err
		}
		if metadata.DeletedAt != nil {
			return ErrNotFound
		}
		if metadata.Version != expectedVersion {
			return ErrVersionConflict
		}
		result, err := tx.ExecContext(ctx, `
			UPDATE credentials SET deleted_at = ?, updated_at = ?
			WHERE id = ? AND current_version = ? AND deleted_at IS NULL
		`, formatCredentialTime(now), formatCredentialTime(now),
			credentialID, expectedVersion)
		if err != nil {
			return fmt.Errorf("soft delete credential: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("count credential deletion: %w", err)
		}
		if affected != 1 {
			return ErrVersionConflict
		}
		deletedAt := now
		metadata.DeletedAt = &deletedAt
		event, err := s.auditEvent(
			principal, writeContext.Actor, "credential.delete", metadata,
			audit.ChangeFields{audit.FieldDeletedAt}, writeContext.Reason,
		)
		if err != nil {
			return ErrAuditUnavailable
		}
		if err := s.audit.AppendTx(ctx, tx, event); err != nil {
			return ErrAuditUnavailable
		}
		return s.saveIdempotency(
			ctx, tx, principal, writeContext, endpoint, requestHash,
			credentialID, expectedVersion, 204, now,
		)
	})
}

func (s *Service) Restore(
	ctx context.Context,
	principal Principal,
	credentialID string,
	expectedVersion uint64,
	writeContext WriteContext,
) (Metadata, error) {
	if credentialID == "" {
		return Metadata{}, ErrNotFound
	}
	if expectedVersion == 0 {
		return Metadata{}, ErrVersionConflict
	}
	if err := validateMutationContext(principal, writeContext); err != nil {
		return Metadata{}, err
	}
	now := s.clock.Now().UTC()
	var restored Metadata
	err := s.repository.withTx(ctx, func(tx *sql.Tx) error {
		metadata, err := s.repository.metadataByID(ctx, tx, credentialID, true)
		if err != nil {
			return err
		}
		if metadata.DeletedAt == nil {
			return ErrNotFound
		}
		if err := authorize(
			principal, resourceForMetadata(metadata), authorization.RestoreCredential,
		); err != nil {
			return err
		}
		if metadata.Version != expectedVersion {
			return ErrVersionConflict
		}
		result, err := tx.ExecContext(ctx, `
			UPDATE credentials SET deleted_at = NULL, updated_at = ?
			WHERE id = ? AND current_version = ? AND deleted_at IS NOT NULL
		`, formatCredentialTime(now), credentialID, expectedVersion)
		if err != nil {
			return fmt.Errorf("restore credential: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("count credential restore: %w", err)
		}
		if affected != 1 {
			return ErrVersionConflict
		}
		metadata.DeletedAt = nil
		event, err := s.auditEvent(
			principal, writeContext.Actor, "credential.restore", metadata,
			audit.ChangeFields{audit.FieldDeletedAt}, writeContext.Reason,
		)
		if err != nil {
			return ErrAuditUnavailable
		}
		if err := s.audit.AppendTx(ctx, tx, event); err != nil {
			return ErrAuditUnavailable
		}
		restored = metadata
		return nil
	})
	if err != nil {
		return Metadata{}, err
	}
	return cloneMetadata(restored), nil
}

func (s *Service) PurgeExpired(
	ctx context.Context,
	principal Principal,
	spaceID string,
) (int64, error) {
	if spaceID == "" {
		return 0, ErrNotFound
	}
	if err := authorize(
		principal,
		authorization.Resource{SpaceID: spaceID},
		authorization.PurgeCredential,
	); err != nil {
		return 0, err
	}
	now := s.clock.Now().UTC()
	cutoff := now.Add(-recycleRetention)
	var purged int64
	err := s.repository.withTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, space_id, name, type, current_version, deleted_at
			FROM credentials
			WHERE space_id = ? AND deleted_at IS NOT NULL AND deleted_at <= ?
			ORDER BY id
		`, spaceID, formatCredentialTime(cutoff))
		if err != nil {
			return fmt.Errorf("find expired credentials: %w", err)
		}
		var expired []Metadata
		for rows.Next() {
			metadata, err := scanMetadataRow(rows)
			if err != nil {
				rows.Close()
				return err
			}
			expired = append(expired, metadata)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close expired credentials: %w", err)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate expired credentials: %w", err)
		}
		for _, metadata := range expired {
			event, err := s.auditEvent(
				principal, audit.Actor{}, "credential.purge", metadata,
				audit.ChangeFields{audit.FieldDeletedAt}, "",
			)
			if err != nil {
				return ErrAuditUnavailable
			}
			if err := s.audit.AppendTx(ctx, tx, event); err != nil {
				return ErrAuditUnavailable
			}
			result, err := tx.ExecContext(
				ctx, `DELETE FROM credentials WHERE id = ?`, metadata.ID,
			)
			if err != nil {
				return fmt.Errorf("purge credential: %w", err)
			}
			affected, err := result.RowsAffected()
			if err != nil {
				return fmt.Errorf("count purged credential: %w", err)
			}
			purged += affected
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return purged, nil
}

func (s *Service) checkIdempotency(
	ctx context.Context,
	tx *sql.Tx,
	principal Principal,
	writeContext WriteContext,
	endpoint, requestHash string,
	now time.Time,
) (*idempotencyResult, error) {
	if principal.Agent == nil {
		return nil, nil
	}
	keyHash := sha256.Sum256([]byte(writeContext.IdempotencyKey))
	result, found, err := lookupIdempotency(
		ctx, tx, principal.Agent.AgentID, endpoint, keyHash[:], now,
	)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	if result.RequestHash != requestHash {
		return nil, ErrIdempotencyConflict
	}
	return &result, nil
}

func (s *Service) saveIdempotency(
	ctx context.Context,
	tx *sql.Tx,
	principal Principal,
	writeContext WriteContext,
	endpoint, requestHash, resourceID string,
	version uint64,
	status int,
	now time.Time,
) error {
	if principal.Agent == nil {
		return nil
	}
	id, err := randomCredentialID("idm_")
	if err != nil {
		return err
	}
	keyHash := sha256.Sum256([]byte(writeContext.IdempotencyKey))
	return storeIdempotency(
		ctx, tx, id, principal.Agent.AgentID, endpoint, keyHash[:], status,
		idempotencyResult{
			RequestHash: requestHash, ResourceID: resourceID, Version: version,
		},
		now,
	)
}

func (s *Service) auditEvent(
	principal Principal,
	actor audit.Actor,
	action string,
	metadata Metadata,
	changeFields audit.ChangeFields,
	reason string,
) (audit.Event, error) {
	if actor == (audit.Actor{}) {
		actor = principal.Actor
	}
	id, err := randomCredentialID("aud_")
	if err != nil {
		return audit.Event{}, err
	}
	return audit.Event{
		ID: id, RequestID: principal.RequestID, CreatedAt: s.clock.Now().UTC(),
		Actor: actor, Action: action, SpaceID: metadata.SpaceID,
		ResourceType: "credential", ResourceID: metadata.ID,
		SourceIP: principal.SourceIP, UserAgent: principal.UserAgent,
		Success: true, ChangeFields: changeFields, Reason: reason,
	}, nil
}

func authorize(
	principal Principal,
	resource authorization.Resource,
	action authorization.Action,
) error {
	switch {
	case principal.Human != nil && principal.Agent == nil:
		if principal.Actor.Type != audit.ActorUser ||
			principal.Actor.ID != principal.Human.Session.UserID {
			return authorization.ErrUnauthenticated
		}
		decision := authorization.DecisionForHuman(*principal.Human, resource, action)
		if err := decision.Err(); err != nil {
			if errors.Is(err, authorization.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		return nil
	case principal.Agent != nil && principal.Human == nil:
		if principal.Actor.Type != audit.ActorAgent ||
			principal.Actor.ID != principal.Agent.AgentID {
			return authorization.ErrUnauthenticated
		}
		decision := authorization.DecisionForAgent(*principal.Agent, resource, action)
		if err := decision.Err(); err != nil {
			if errors.Is(err, authorization.ErrNotFound) ||
				errors.Is(err, authorization.ErrDenied) {
				return ErrNotFound
			}
			return err
		}
		return nil
	default:
		return authorization.ErrUnauthenticated
	}
}

func validateCreateInput(input CreateInput) error {
	if !validIdentifier(input.SpaceID) ||
		!validText(input.DisplayName, 256, false) ||
		!input.Type.Valid() {
		return ErrInvalidInput
	}
	if err := validateTags(input.Tags); err != nil {
		return err
	}
	return validateAssetIDs(input.AssetIDs)
}

func validateMutationContext(
	principal Principal,
	writeContext WriteContext,
) error {
	if principal.Actor != writeContext.Actor {
		return authorization.ErrDenied
	}
	if principal.Agent != nil {
		if !validText(writeContext.IdempotencyKey, 256, false) {
			return ErrIdempotencyRequired
		}
		if !validText(strings.TrimSpace(writeContext.Reason), audit.MaxAuditTextBytes, false) {
			return ErrReasonRequired
		}
	}
	return nil
}

func validateListFilter(filter ListFilter) (int, error) {
	if !validIdentifier(filter.SpaceID) ||
		(filter.Type != "" && !filter.Type.Valid()) ||
		(filter.After != "" && !validIdentifier(filter.After)) {
		return 0, ErrInvalidInput
	}
	if err := validateTags(filter.Tags); err != nil {
		return 0, err
	}
	limit := filter.Limit
	if limit == 0 {
		limit = defaultListLimit
	}
	if limit < 1 || limit > maxListLimit {
		return 0, ErrInvalidInput
	}
	return limit, nil
}

func validateTags(tags map[string]string) error {
	if len(tags) > 64 {
		return ErrInvalidInput
	}
	for key, value := range tags {
		if !validText(strings.TrimSpace(key), 128, false) ||
			!validText(value, 512, true) {
			return ErrInvalidInput
		}
	}
	return nil
}

func validateAssetIDs(assetIDs []string) error {
	if len(assetIDs) > 256 {
		return ErrInvalidInput
	}
	seen := make(map[string]struct{}, len(assetIDs))
	for _, assetID := range assetIDs {
		if !validIdentifier(assetID) {
			return ErrInvalidInput
		}
		if _, duplicate := seen[assetID]; duplicate {
			return ErrInvalidInput
		}
		seen[assetID] = struct{}{}
	}
	return nil
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

func validText(value string, maxBytes int, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || len(value) > maxBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character <= 0x1f || (character >= 0x7f && character <= 0x9f) {
			return false
		}
	}
	return true
}

func normalizedAssetIDs(assetIDs []string) []string {
	cloned := append([]string(nil), assetIDs...)
	slices.Sort(cloned)
	return cloned
}

func cloneTags(tags map[string]string) map[string]string {
	cloned := make(map[string]string, len(tags))
	for key, value := range tags {
		cloned[key] = value
	}
	return cloned
}

func cloneMetadata(metadata Metadata) Metadata {
	cloned := metadata
	cloned.Tags = cloneTags(metadata.Tags)
	cloned.AssetIDs = append([]string(nil), metadata.AssetIDs...)
	if metadata.DeletedAt != nil {
		deletedAt := *metadata.DeletedAt
		cloned.DeletedAt = &deletedAt
	}
	return cloned
}

func resourceForMetadata(metadata Metadata) authorization.Resource {
	return authorization.Resource{
		SpaceID: metadata.SpaceID, ResourceID: metadata.ID, Labels: metadata.Tags,
	}
}

func inputWithoutPayload(input CreateInput) CreateInput {
	input.Payload = nil
	return input
}

func requestFingerprint(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalidInput
	}
	defer clearBytes(encoded)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func randomCredentialID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("generate credential identifier")
	}
	return prefix + hex.EncodeToString(raw[:]), nil
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
		return fmt.Errorf("validate credential Space: %w", err)
	}
	return nil
}

func insertVersion(
	ctx context.Context,
	tx *sql.Tx,
	metadata Metadata,
	envelope cryptobox.Envelope,
	principal Principal,
	now time.Time,
) error {
	id, err := randomCredentialID("crv_")
	if err != nil {
		return err
	}
	var createdByUserID any
	if principal.Human != nil {
		createdByUserID = principal.Human.Session.UserID
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO credential_versions (
			id, credential_id, version, payload_ciphertext, payload_nonce,
			wrapped_data_key, wrap_nonce, created_by_user_id, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, metadata.ID, metadata.Version, envelope.Ciphertext, envelope.Nonce[:],
		envelope.WrappedDataKey, envelope.WrapNonce[:], createdByUserID,
		formatCredentialTime(now))
	if err != nil {
		return fmt.Errorf("insert credential version: %w", err)
	}
	return nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
