package audit

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"opswarden/internal/storage"
)

func TestEventRejectsSensitiveFieldNames(t *testing.T) {
	for _, field := range []string{
		"password", "api_token", "private_key", "totp_seed", "username",
		"old_value", "new_value", "value",
	} {
		t.Run(field, func(t *testing.T) {
			event := validEvent()
			event.ChangeFields = ChangeFields{field}

			err := Validate(event)

			if !errors.Is(err, ErrSensitiveAuditField) {
				t.Fatalf("got %v", err)
			}
			if strings.Contains(strings.ToLower(err.Error()), field) {
				t.Fatalf("error echoed rejected field: %v", err)
			}
		})
	}
}

func TestEventAcceptsOnlyMetadataChangeFieldAllowlist(t *testing.T) {
	event := validEvent()
	event.ChangeFields = ChangeFields{
		FieldDisplayName,
		FieldTags,
		FieldAssetLinks,
		FieldCredentialType,
		FieldExpiresAt,
	}
	if err := Validate(event); err != nil {
		t.Fatalf("metadata allowlist rejected: %v", err)
	}

	event.ChangeFields = ChangeFields{"harmless_but_unregistered"}
	err := Validate(event)
	if !errors.Is(err, ErrInvalidChangeField) {
		t.Fatalf("unregistered field error = %v", err)
	}
	if strings.Contains(err.Error(), "harmless_but_unregistered") {
		t.Fatalf("error echoed rejected field: %v", err)
	}
}

func TestEventShapeCannotCarryArbitraryStructuredValues(t *testing.T) {
	eventType := reflect.TypeFor[Event]()
	for index := 0; index < eventType.NumField(); index++ {
		field := eventType.Field(index)
		switch field.Type.Kind() {
		case reflect.Map, reflect.Interface:
			t.Fatalf("Event field %s permits arbitrary structured values", field.Name)
		}
	}
}

func TestActorFingerprintIsExactlySixteenLowercaseHexCharacters(t *testing.T) {
	for name, fingerprint := range map[string]string{
		"too short":   "0123456789abcde",
		"too long":    "0123456789abcdef0",
		"uppercase":   "0123456789abcdeF",
		"non hex":     "0123456789abcdeg",
		"raw token":   "token_live_value",
		"raw session": "session_cookie_x",
	} {
		t.Run(name, func(t *testing.T) {
			event := validEvent()
			event.Actor.Fingerprint = fingerprint
			if err := Validate(event); !errors.Is(err, ErrInvalidActor) {
				t.Fatalf("got %v", err)
			}
		})
	}

	event := validEvent()
	event.Actor.Fingerprint = "0123456789abcdef"
	if err := Validate(event); err != nil {
		t.Fatalf("valid fingerprint rejected: %v", err)
	}
}

func TestActorRequiresTypedIDAndSeparateTokenID(t *testing.T) {
	for name, actor := range map[string]Actor{
		"missing type": {
			ID: "user-1", TokenID: "session-1", Fingerprint: "0123456789abcdef",
		},
		"unknown type": {
			Type: "service", ID: "service-1", TokenID: "token-1",
			Fingerprint: "0123456789abcdef",
		},
		"missing actor ID": {
			Type: ActorUser, TokenID: "session-1", Fingerprint: "0123456789abcdef",
		},
		"missing token ID": {
			Type: ActorUser, ID: "user-1", Fingerprint: "0123456789abcdef",
		},
	} {
		t.Run(name, func(t *testing.T) {
			event := validEvent()
			event.Actor = actor
			if err := Validate(event); !errors.Is(err, ErrInvalidActor) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestReasonAndUserAgentBoundariesRejectInvalidUTF8AndControls(t *testing.T) {
	valid512 := strings.Repeat("a", MaxAuditTextBytes)
	for name, mutate := range map[string]func(*Event){
		"reason at limit":     func(event *Event) { event.Reason = valid512 },
		"user agent at limit": func(event *Event) { event.UserAgent = valid512 },
	} {
		t.Run(name, func(t *testing.T) {
			event := validEvent()
			mutate(&event)
			if err := Validate(event); err != nil {
				t.Fatalf("boundary rejected: %v", err)
			}
		})
	}

	secret := "do-not-echo-this-secret"
	for name, mutate := range map[string]func(*Event){
		"reason too long": func(event *Event) {
			event.Reason = strings.Repeat("a", MaxAuditTextBytes+1) + secret
		},
		"user agent too long": func(event *Event) {
			event.UserAgent = strings.Repeat("a", MaxAuditTextBytes+1) + secret
		},
		"reason newline": func(event *Event) { event.Reason = secret + "\n" },
		"user agent tab": func(event *Event) { event.UserAgent = secret + "\t" },
		"reason C1":      func(event *Event) { event.Reason = secret + "\u0085" },
		"reason invalid UTF-8": func(event *Event) {
			event.Reason = string([]byte{0xff}) + secret
		},
	} {
		t.Run(name, func(t *testing.T) {
			event := validEvent()
			mutate(&event)
			err := Validate(event)
			if !errors.Is(err, ErrInvalidAuditText) {
				t.Fatalf("got %v", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error echoed rejected value: %v", err)
			}
		})
	}
}

func TestSourceIPMustBeCanonical(t *testing.T) {
	event := validEvent()
	event.SourceIP = "2001:0db8::1"
	if err := Validate(event); !errors.Is(err, ErrInvalidSourceIP) {
		t.Fatalf("non-canonical IP error = %v", err)
	}

	event.SourceIP = "2001:db8::1"
	if err := Validate(event); err != nil {
		t.Fatalf("canonical IP rejected: %v", err)
	}
}

func TestAppendTxUsesTheCallerTransaction(t *testing.T) {
	h := newAuditHarness(t)
	event := h.event("audit-rollback", h.now)

	tx, err := h.db.Writer.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.repository.AppendTx(h.ctx, tx, event); err != nil {
		t.Fatal(err)
	}
	var inside int
	if err := tx.QueryRowContext(h.ctx,
		`SELECT count(*) FROM audit_events WHERE id = ?`, event.ID,
	).Scan(&inside); err != nil {
		t.Fatal(err)
	}
	if inside != 1 {
		t.Fatalf("rows visible inside caller transaction = %d", inside)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if got := h.countEvents(event.ID); got != 0 {
		t.Fatalf("AppendTx escaped caller rollback: %d rows", got)
	}

	event.ID = "audit-commit"
	tx, err = h.db.Writer.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.repository.AppendTx(h.ctx, tx, event); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := h.countEvents(event.ID); got != 1 {
		t.Fatalf("committed rows = %d", got)
	}
}

func TestRecordReadBeforeReturnCommitsDurablyBeforePayloadEscapes(t *testing.T) {
	h := newAuditHarness(t)
	event := h.event("audit-durable-read", h.now)

	value, err := h.readCredential(event, []byte("decrypted credential fixture"))

	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "decrypted credential fixture" {
		t.Fatalf("payload = %q", value)
	}
	if got := h.countEvents(event.ID); got != 1 {
		t.Fatalf("reader observed %d audit rows after return", got)
	}
}

func TestReadFailsWithoutPayloadWhenAuditInsertFails(t *testing.T) {
	h := newAuditHarness(t)
	h.mustExec(`
		CREATE TRIGGER fail_next_audit_insert
		BEFORE INSERT ON audit_events
		BEGIN
			SELECT RAISE(ABORT, 'forced audit failure');
		END
	`)
	payload := []byte("never-return-this-credential")

	value, err := h.readCredential(h.event("audit-failed-read", h.now), payload)

	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("got %v", err)
	}
	if len(value) != 0 {
		t.Fatalf("payload escaped: %q", value)
	}
	if strings.Contains(err.Error(), string(payload)) {
		t.Fatalf("error echoed payload: %v", err)
	}
	if got := h.countEvents(""); got != 0 {
		t.Fatalf("failed insert left %d audit rows", got)
	}
}

func TestReadMapsWriterUnavailabilityWithoutReturningPayload(t *testing.T) {
	h := newAuditHarness(t)
	if err := h.db.Writer.Close(); err != nil {
		t.Fatal(err)
	}
	payload := []byte("never-return-this-either")

	value, err := h.readCredential(h.event("audit-writer-closed", h.now), payload)

	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("got %v", err)
	}
	if len(value) != 0 {
		t.Fatalf("payload escaped: %q", value)
	}
	if strings.Contains(err.Error(), string(payload)) ||
		strings.Contains(strings.ToLower(err.Error()), "database is closed") {
		t.Fatalf("error exposed rejected or storage value: %v", err)
	}
}

func TestAppendTxPersistsOnlyTheTypedAllowlist(t *testing.T) {
	h := newAuditHarness(t)
	event := h.event("audit-roundtrip", h.now)
	event.ChangeFields = ChangeFields{FieldDisplayName, FieldTags}
	event.Reason = "approved rotation"
	event.UserAgent = "OpsWarden CLI/1"

	if err := h.service.RecordReadBeforeReturn(h.ctx, event); err != nil {
		t.Fatal(err)
	}
	var metadata string
	if err := h.db.Reader.QueryRowContext(h.ctx,
		`SELECT metadata_json FROM audit_events WHERE id = ?`, event.ID,
	).Scan(&metadata); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"password", "old_value", "new_value", "payload", "private_key",
		"master_key", "session_id", "raw_token",
	} {
		if strings.Contains(strings.ToLower(metadata), forbidden) {
			t.Fatalf("metadata contains forbidden key %q: %s", forbidden, metadata)
		}
	}

	rows, next, err := h.service.List(h.ctx, Filter{SpaceID: "space-1", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || next != "" {
		t.Fatalf("rows=%+v next=%q", rows, next)
	}
	if !reflect.DeepEqual(rows[0], event) {
		t.Fatalf("round trip event = %+v, want %+v", rows[0], event)
	}
}

func TestListUsesStableDescendingKeysetPaginationWithoutDuplicatesOrGaps(t *testing.T) {
	h := newAuditHarness(t)
	events := []Event{
		h.event("audit-a", h.now.Add(-2*time.Second)),
		h.event("audit-b", h.now.Add(-time.Second)),
		h.event("audit-c", h.now),
		h.event("audit-d", h.now),
		h.event("audit-e", h.now.Add(time.Second)),
	}
	for _, event := range events {
		if err := h.service.RecordReadBeforeReturn(h.ctx, event); err != nil {
			t.Fatal(err)
		}
	}

	var got []string
	var after Cursor
	for page := 0; ; page++ {
		rows, next, err := h.service.List(h.ctx, Filter{
			SpaceID: "space-1", Limit: 2, After: after,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range rows {
			got = append(got, event.ID)
		}
		if page == 0 {
			newer := h.event("audit-newer", h.now.Add(2*time.Second))
			if err := h.service.RecordReadBeforeReturn(h.ctx, newer); err != nil {
				t.Fatal(err)
			}
		}
		if next == "" {
			break
		}
		if len(next) > MaxCursorBytes {
			t.Fatalf("cursor length = %d", len(next))
		}
		after = next
	}

	want := []string{"audit-e", "audit-d", "audit-c", "audit-b", "audit-a"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ordered IDs = %v, want %v", got, want)
	}
	seen := make(map[string]struct{}, len(got))
	for _, id := range got {
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("duplicate event %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestListFiltersActorActionAndResource(t *testing.T) {
	h := newAuditHarness(t)
	userEvent := h.event("audit-user", h.now)
	userEvent.Action = "credential.read"
	userEvent.ResourceID = "credential-1"
	if err := h.service.RecordReadBeforeReturn(h.ctx, userEvent); err != nil {
		t.Fatal(err)
	}
	agentEvent := h.event("audit-agent", h.now.Add(time.Second))
	agentEvent.Actor = Actor{
		Type: ActorAgent, ID: "agent-1", TokenID: "agent-token-1",
		Fingerprint: "fedcba9876543210",
	}
	agentEvent.Action = "credential.update"
	agentEvent.ResourceID = "credential-2"
	if err := h.service.RecordReadBeforeReturn(h.ctx, agentEvent); err != nil {
		t.Fatal(err)
	}

	rows, _, err := h.service.List(h.ctx, Filter{
		SpaceID: "space-1", ActorType: ActorAgent, ActorID: "agent-1",
		Action: "credential.update", ResourceType: "credential",
		ResourceID: "credential-2", Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != agentEvent.ID {
		t.Fatalf("filtered rows = %+v", rows)
	}
}

func TestCursorDecoderRejectsMalformedNonCanonicalAndOversizedInputs(t *testing.T) {
	h := newAuditHarness(t)
	rawURL := func(value string) Cursor {
		return Cursor(base64.RawURLEncoding.EncodeToString([]byte(value)))
	}
	for name, cursor := range map[string]Cursor{
		"invalid base64":         "%%%%",
		"padding":                Cursor(base64.URLEncoding.EncodeToString([]byte(`{"v":1}`))),
		"unknown field":          rawURL(`{"v":1,"created_at":"2026-07-28T12:00:00Z","id":"audit-1","extra":true}`),
		"trailing JSON":          rawURL(`{"v":1,"created_at":"2026-07-28T12:00:00Z","id":"audit-1"}{}`),
		"wrong version":          rawURL(`{"v":2,"created_at":"2026-07-28T12:00:00Z","id":"audit-1"}`),
		"non UTC":                rawURL(`{"v":1,"created_at":"2026-07-28T20:00:00+08:00","id":"audit-1"}`),
		"non canonical fraction": rawURL(`{"v":1,"created_at":"2026-07-28T12:00:00.000Z","id":"audit-1"}`),
		"missing ID":             rawURL(`{"v":1,"created_at":"2026-07-28T12:00:00Z","id":""}`),
		"oversized":              Cursor(strings.Repeat("a", MaxCursorBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := h.service.List(h.ctx, Filter{
				SpaceID: "space-1", Limit: 10, After: cursor,
			})
			if !errors.Is(err, ErrInvalidCursor) {
				t.Fatalf("got %v", err)
			}
			if strings.Contains(err.Error(), string(cursor)) {
				t.Fatalf("error echoed cursor")
			}
		})
	}
}

func TestPurgeBeforeDeletesOnlyEventsStrictlyOlderThanBoundary(t *testing.T) {
	h := newAuditHarness(t)
	cutoff := time.Date(2025, 7, 28, 12, 0, 0, 0, time.UTC)
	for _, event := range []Event{
		h.event("audit-before", cutoff.Add(-time.Nanosecond)),
		h.event("audit-boundary", cutoff),
		h.event("audit-after", cutoff.Add(time.Nanosecond)),
	} {
		if err := h.service.RecordReadBeforeReturn(h.ctx, event); err != nil {
			t.Fatal(err)
		}
	}

	deleted, err := h.service.PurgeBefore(h.ctx, cutoff)

	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d", deleted)
	}
	rows, _, err := h.service.List(h.ctx, Filter{SpaceID: "space-1", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, event := range rows {
		got = append(got, event.ID)
	}
	want := []string{"audit-after", "audit-boundary"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("remaining IDs = %v, want %v", got, want)
	}
}

func TestPurgeBeforeUsesCallerCutoffForOneYearRetentionContract(t *testing.T) {
	h := newAuditHarness(t)
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	oneYearCutoff := now.AddDate(-1, 0, 0)
	for _, event := range []Event{
		h.event("audit-expired", oneYearCutoff.Add(-time.Nanosecond)),
		h.event("audit-retained", oneYearCutoff),
	} {
		if err := h.service.RecordReadBeforeReturn(h.ctx, event); err != nil {
			t.Fatal(err)
		}
	}

	deleted, err := h.service.PurgeBefore(h.ctx, oneYearCutoff)

	if err != nil || deleted != 1 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
	if h.countEvents("audit-retained") != 1 {
		t.Fatal("event exactly one calendar year old was purged")
	}
}

func validEvent() Event {
	return Event{
		ID:        "audit-1",
		RequestID: "request-1",
		CreatedAt: time.Date(2026, 7, 28, 12, 0, 0, 123, time.UTC),
		Actor: Actor{
			Type:        ActorUser,
			ID:          "user-1",
			TokenID:     "session-1",
			Fingerprint: "0123456789abcdef",
		},
		Action:       "credential.read",
		SpaceID:      "space-1",
		ResourceType: "credential",
		ResourceID:   "credential-1",
		SourceIP:     "192.0.2.10",
		UserAgent:    "OpsWarden test client",
		Success:      true,
		ChangeFields: ChangeFields{},
		Reason:       "incident response",
	}
}

type auditHarness struct {
	ctx        context.Context
	db         *storage.DB
	repository *Repository
	service    *Service
	now        time.Time
}

func newAuditHarness(t *testing.T) *auditHarness {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close audit database: %v", err)
		}
	})
	repository, err := NewRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	h := &auditHarness{
		ctx: context.Background(), db: db, repository: repository, service: service,
		now: time.Date(2026, 7, 28, 12, 0, 0, 123456789, time.UTC),
	}
	h.mustExec(`
		INSERT INTO users
			(id, email, normalized_email, password_hash, system_role)
		VALUES
			('user-1', 'user@example.com', 'user@example.com', X'01', 'member')
	`)
	h.mustExec(`
		INSERT INTO agents (id, name, created_by_user_id)
		VALUES ('agent-1', 'Automation', 'user-1')
	`)
	h.mustExec(`INSERT INTO spaces (id, name) VALUES ('space-1', 'Production')`)
	return h
}

func (h *auditHarness) event(id string, createdAt time.Time) Event {
	event := validEvent()
	event.ID = id
	event.CreatedAt = createdAt
	return event
}

func (h *auditHarness) readCredential(event Event, decrypted []byte) ([]byte, error) {
	requestLocal := append([]byte(nil), decrypted...)
	if err := h.service.RecordReadBeforeReturn(h.ctx, event); err != nil {
		clear(requestLocal)
		return nil, err
	}
	return requestLocal, nil
}

func (h *auditHarness) countEvents(id string) int {
	query := `SELECT count(*) FROM audit_events`
	args := []any(nil)
	if id != "" {
		query += ` WHERE id = ?`
		args = append(args, id)
	}
	var count int
	if err := h.db.Reader.QueryRowContext(h.ctx, query, args...).Scan(&count); err != nil {
		panic(err)
	}
	return count
}

func (h *auditHarness) mustExec(query string, args ...any) {
	if _, err := h.db.Writer.ExecContext(h.ctx, query, args...); err != nil {
		panic(err)
	}
}

var _ interface {
	AppendTx(context.Context, *sql.Tx, Event) error
} = (*Repository)(nil)
