package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"time"

	"opswarden/internal/storage"
)

const auditMetadataVersion = 1

type Repository struct {
	db *storage.DB
}

type auditMetadata struct {
	Version      int          `json:"v"`
	RequestID    string       `json:"request_id"`
	ActorType    ActorType    `json:"actor_type"`
	Fingerprint  string       `json:"fingerprint"`
	SourceIP     string       `json:"source_ip"`
	UserAgent    string       `json:"user_agent,omitempty"`
	Success      bool         `json:"success"`
	ErrorCode    string       `json:"error_code,omitempty"`
	ChangeFields ChangeFields `json:"change_fields"`
	Reason       string       `json:"reason,omitempty"`
}

func NewRepository(db *storage.DB) (*Repository, error) {
	if db == nil || db.Writer == nil || db.Reader == nil {
		return nil, errors.New("audit database is required")
	}
	return &Repository{db: db}, nil
}

func (r *Repository) AppendTx(ctx context.Context, tx *sql.Tx, event Event) error {
	if r == nil || r.db == nil || tx == nil {
		return ErrAuditUnavailable
	}
	if err := Validate(event); err != nil {
		return err
	}
	metadataJSON, err := encodeMetadata(event)
	if err != nil {
		return ErrAuditUnavailable
	}
	var actorUserID, actorAgentID any
	switch event.Actor.Type {
	case ActorUser:
		actorUserID = event.Actor.ID
	case ActorAgent:
		actorAgentID = event.Actor.ID
	case ActorAnonymous, ActorSystem:
		// Anonymous authentication events intentionally have no owner FK.
	default:
		return ErrInvalidActor
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (
			id,
			space_id,
			actor_user_id,
			actor_agent_id,
			action,
			entity_type,
			entity_id,
			metadata_json,
			created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, event.ID, nullableString(event.SpaceID), actorUserID, actorAgentID,
		event.Action, event.ResourceType, nullableString(event.ResourceID),
		metadataJSON, formatStorageTime(event.CreatedAt)); err != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func encodeMetadata(event Event) ([]byte, error) {
	changeFields := event.ChangeFields
	if changeFields == nil {
		changeFields = ChangeFields{}
	}
	return json.Marshal(auditMetadata{
		Version:      auditMetadataVersion,
		RequestID:    event.RequestID,
		ActorType:    event.Actor.Type,
		Fingerprint:  event.Actor.Fingerprint,
		SourceIP:     event.SourceIP,
		UserAgent:    event.UserAgent,
		Success:      event.Success,
		ErrorCode:    event.ErrorCode,
		ChangeFields: changeFields,
		Reason:       event.Reason,
	})
}

func decodeMetadata(encoded []byte) (auditMetadata, error) {
	if len(encoded) == 0 || len(encoded) > 4096 {
		return auditMetadata{}, ErrAuditUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var metadata auditMetadata
	if err := decoder.Decode(&metadata); err != nil {
		return auditMetadata{}, ErrAuditUnavailable
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return auditMetadata{}, ErrAuditUnavailable
	}
	canonical, err := json.Marshal(metadata)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return auditMetadata{}, ErrAuditUnavailable
	}
	if metadata.Version != auditMetadataVersion {
		return auditMetadata{}, ErrAuditUnavailable
	}
	return metadata, nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

const storageTimeLayout = "2006-01-02T15:04:05.000000000Z"

func formatStorageTime(value time.Time) string {
	return value.UTC().Format(storageTimeLayout)
}

func parseStorageTime(value string) (time.Time, error) {
	parsed, err := time.Parse(storageTimeLayout, value)
	if err != nil || formatStorageTime(parsed) != value {
		return time.Time{}, ErrAuditUnavailable
	}
	return parsed, nil
}
