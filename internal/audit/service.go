package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"opswarden/internal/storage"
)

const (
	DefaultListLimit = 100
	MaxListLimit     = 500
	MaxCursorBytes   = 512
	cursorVersion    = 1
)

type Cursor string

type Filter struct {
	SpaceID      string
	ActorType    ActorType
	ActorID      string
	Action       string
	ResourceType string
	ResourceID   string
	After        Cursor
	Limit        int
}

type Service struct {
	repository *Repository
}

type cursorPayload struct {
	Version   int    `json:"v"`
	CreatedAt string `json:"created_at"`
	ID        string `json:"id"`
}

var strictRawBase64URL = base64.RawURLEncoding.Strict()

func NewService(repository *Repository) (*Service, error) {
	if repository == nil || repository.db == nil {
		return nil, errors.New("audit repository is required")
	}
	return &Service{repository: repository}, nil
}

func (s *Service) RecordReadBeforeReturn(ctx context.Context, event Event) error {
	if s == nil || s.repository == nil {
		return ErrAuditUnavailable
	}
	if err := Validate(event); err != nil {
		return err
	}
	if err := storage.WithTx(ctx, s.repository.db, func(tx *sql.Tx) error {
		return s.repository.AppendTx(ctx, tx, event)
	}); err != nil {
		return ErrAuditUnavailable
	}
	return nil
}

func (s *Service) List(ctx context.Context, filter Filter) ([]Event, Cursor, error) {
	if s == nil || s.repository == nil || s.repository.db == nil {
		return nil, "", ErrAuditUnavailable
	}
	limit, err := validateFilter(filter)
	if err != nil {
		return nil, "", err
	}

	query := strings.Builder{}
	query.WriteString(`
		SELECT
			id,
			space_id,
			actor_user_id,
			actor_agent_id,
			action,
			entity_type,
			entity_id,
			metadata_json,
			created_at
		FROM audit_events
		WHERE 1 = 1
	`)
	args := make([]any, 0, 12)
	if filter.SpaceID != "" {
		query.WriteString(` AND space_id = ?`)
		args = append(args, filter.SpaceID)
	}
	switch filter.ActorType {
	case ActorUser:
		query.WriteString(` AND actor_user_id IS NOT NULL`)
	case ActorAgent:
		query.WriteString(` AND actor_agent_id IS NOT NULL`)
	}
	if filter.ActorID != "" {
		if filter.ActorType == ActorUser {
			query.WriteString(` AND actor_user_id = ?`)
		} else {
			query.WriteString(` AND actor_agent_id = ?`)
		}
		args = append(args, filter.ActorID)
	}
	if filter.Action != "" {
		query.WriteString(` AND action = ?`)
		args = append(args, filter.Action)
	}
	if filter.ResourceType != "" {
		query.WriteString(` AND entity_type = ?`)
		args = append(args, filter.ResourceType)
	}
	if filter.ResourceID != "" {
		query.WriteString(` AND entity_id = ?`)
		args = append(args, filter.ResourceID)
	}
	if filter.After != "" {
		createdAt, id, err := decodeCursor(filter.After)
		if err != nil {
			return nil, "", err
		}
		cursorTime := formatStorageTime(createdAt)
		query.WriteString(` AND (created_at < ? OR (created_at = ? AND id < ?))`)
		args = append(args, cursorTime, cursorTime, id)
	}
	query.WriteString(` ORDER BY created_at DESC, id DESC LIMIT ?`)
	args = append(args, limit+1)

	rows, err := s.repository.db.Reader.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, "", ErrAuditUnavailable
	}
	defer rows.Close()

	events := make([]Event, 0, limit)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, "", err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, "", ErrAuditUnavailable
	}
	if len(events) <= limit {
		return events, "", nil
	}
	events = events[:limit]
	next, err := encodeCursor(events[len(events)-1])
	if err != nil {
		return nil, "", err
	}
	return events, next, nil
}

func (s *Service) PurgeBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.repository == nil || s.repository.db == nil || cutoff.IsZero() {
		return 0, ErrAuditUnavailable
	}
	var deleted int64
	err := storage.WithTx(ctx, s.repository.db, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx,
			`DELETE FROM audit_events WHERE created_at < ?`,
			formatStorageTime(cutoff),
		)
		if err != nil {
			return ErrAuditUnavailable
		}
		deleted, err = result.RowsAffected()
		if err != nil {
			return ErrAuditUnavailable
		}
		return nil
	})
	if err != nil {
		return 0, ErrAuditUnavailable
	}
	return deleted, nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanEvent(row rowScanner) (Event, error) {
	var event Event
	var spaceID, actorUserID, actorAgentID, resourceID sql.NullString
	var metadataJSON []byte
	var createdAt string
	if err := row.Scan(
		&event.ID,
		&spaceID,
		&actorUserID,
		&actorAgentID,
		&event.Action,
		&event.ResourceType,
		&resourceID,
		&metadataJSON,
		&createdAt,
	); err != nil {
		return Event{}, ErrAuditUnavailable
	}
	metadata, err := decodeMetadata(metadataJSON)
	if err != nil {
		return Event{}, err
	}
	event.CreatedAt, err = parseStorageTime(createdAt)
	if err != nil {
		return Event{}, err
	}
	event.SpaceID = spaceID.String
	event.ResourceID = resourceID.String
	event.RequestID = metadata.RequestID
	event.Actor = Actor{
		Type: metadata.ActorType, Fingerprint: metadata.Fingerprint,
	}
	switch {
	case actorUserID.Valid && !actorAgentID.Valid && metadata.ActorType == ActorUser:
		event.Actor.ID = actorUserID.String
	case actorAgentID.Valid && !actorUserID.Valid && metadata.ActorType == ActorAgent:
		event.Actor.ID = actorAgentID.String
	default:
		return Event{}, ErrAuditUnavailable
	}
	event.SourceIP = metadata.SourceIP
	event.UserAgent = metadata.UserAgent
	event.Success = metadata.Success
	event.ErrorCode = metadata.ErrorCode
	event.ChangeFields = metadata.ChangeFields
	event.Reason = metadata.Reason
	if err := Validate(event); err != nil {
		return Event{}, ErrAuditUnavailable
	}
	return event, nil
}

func validateFilter(filter Filter) (int, error) {
	limit := filter.Limit
	if limit == 0 {
		limit = DefaultListLimit
	}
	if limit < 1 || limit > MaxListLimit {
		return 0, ErrInvalidFilter
	}
	if filter.SpaceID != "" && !validIdentifier(filter.SpaceID, 256) {
		return 0, ErrInvalidFilter
	}
	if filter.ActorType != "" && filter.ActorType != ActorUser && filter.ActorType != ActorAgent {
		return 0, ErrInvalidFilter
	}
	if filter.ActorID != "" &&
		(filter.ActorType == "" || !validIdentifier(filter.ActorID, 256)) {
		return 0, ErrInvalidFilter
	}
	if filter.Action != "" && !validAction(filter.Action) {
		return 0, ErrInvalidFilter
	}
	if filter.ResourceType != "" && !validResourceType(filter.ResourceType) {
		return 0, ErrInvalidFilter
	}
	if filter.ResourceID != "" && !validIdentifier(filter.ResourceID, 256) {
		return 0, ErrInvalidFilter
	}
	return limit, nil
}

func encodeCursor(event Event) (Cursor, error) {
	payload := cursorPayload{
		Version: cursorVersion, CreatedAt: event.CreatedAt.UTC().Format(time.RFC3339Nano),
		ID: event.ID,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", ErrInvalidCursor
	}
	cursor := strictRawBase64URL.EncodeToString(encoded)
	if len(cursor) > MaxCursorBytes {
		return "", ErrInvalidCursor
	}
	return Cursor(cursor), nil
}

func decodeCursor(cursor Cursor) (time.Time, string, error) {
	if cursor == "" || len(cursor) > MaxCursorBytes {
		return time.Time{}, "", ErrInvalidCursor
	}
	for _, character := range cursor {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' {
			continue
		}
		return time.Time{}, "", ErrInvalidCursor
	}
	decoded, err := strictRawBase64URL.DecodeString(string(cursor))
	if err != nil || len(decoded) == 0 || len(decoded) > MaxCursorBytes {
		return time.Time{}, "", ErrInvalidCursor
	}
	if strictRawBase64URL.EncodeToString(decoded) != string(cursor) {
		return time.Time{}, "", ErrInvalidCursor
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.DisallowUnknownFields()
	var payload cursorPayload
	if err := decoder.Decode(&payload); err != nil {
		return time.Time{}, "", ErrInvalidCursor
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return time.Time{}, "", ErrInvalidCursor
	}
	canonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonical, decoded) {
		return time.Time{}, "", ErrInvalidCursor
	}
	if payload.Version != cursorVersion || !validIdentifier(payload.ID, 256) {
		return time.Time{}, "", ErrInvalidCursor
	}
	createdAt, err := time.Parse(time.RFC3339Nano, payload.CreatedAt)
	if err != nil || createdAt.UTC().Format(time.RFC3339Nano) != payload.CreatedAt {
		return time.Time{}, "", ErrInvalidCursor
	}
	return createdAt, payload.ID, nil
}
