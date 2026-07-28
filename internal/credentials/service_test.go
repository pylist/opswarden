package credentials

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/cryptobox"
	"opswarden/internal/identity"
	"opswarden/internal/storage"
)

type credentialTestClock struct{ now time.Time }

func (c *credentialTestClock) Now() time.Time { return c.now }

type credentialAuditAppender struct {
	mu       sync.Mutex
	nextErr  error
	delegate *audit.Repository
}

func (a *credentialAuditAppender) AppendTx(
	ctx context.Context,
	tx *sql.Tx,
	event audit.Event,
) error {
	a.mu.Lock()
	err := a.nextErr
	a.nextErr = nil
	a.mu.Unlock()
	if err != nil {
		return err
	}
	return a.delegate.AppendTx(ctx, tx, event)
}

func (a *credentialAuditAppender) FailNextInsert(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nextErr = err
}

type credentialHarness struct {
	t          *testing.T
	ctx        context.Context
	db         *storage.DB
	dbPath     string
	service    *Service
	audit      *credentialAuditAppender
	clock      *credentialTestClock
	spaceID    string
	otherSpace string
	editor     Principal
	reader     Principal
	agent      Principal
	other      Principal
}

func newCredentialHarness(t *testing.T) *credentialHarness {
	t.Helper()
	path := filepath.Join(t.TempDir(), "opswarden.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	_, err = db.Writer.ExecContext(ctx, `
		INSERT INTO users (id, email, normalized_email, password_hash, system_role)
		VALUES
		  ('usr_editor', 'editor@example.test', 'editor@example.test', X'01', 'member'),
		  ('usr_reader', 'reader@example.test', 'reader@example.test', X'01', 'member'),
		  ('usr_other', 'other@example.test', 'other@example.test', X'01', 'member');
		INSERT INTO spaces (id, name) VALUES ('spc_main', 'Main'), ('spc_other', 'Other');
		INSERT INTO space_memberships (space_id, user_id, role) VALUES
		  ('spc_main', 'usr_editor', 'editor'),
		  ('spc_main', 'usr_reader', 'reader'),
		  ('spc_other', 'usr_other', 'reader');
		INSERT INTO agents (id, name, created_by_user_id) VALUES ('agt_writer', 'Writer', 'usr_editor');
	`)
	if err != nil {
		t.Fatal(err)
	}
	auditRepository, err := audit.NewRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	appender := &credentialAuditAppender{delegate: auditRepository}
	clock := &credentialTestClock{now: now}
	var master [32]byte
	for index := range master {
		master[index] = byte(index + 1)
	}
	service, err := NewService(db, cryptobox.New(master), appender, clock)
	if err != nil {
		t.Fatal(err)
	}
	h := &credentialHarness{
		t: t, ctx: ctx, db: db, dbPath: path, service: service,
		audit: appender, clock: clock, spaceID: "spc_main", otherSpace: "spc_other",
	}
	h.editor = humanCredentialPrincipal("usr_editor", "spc_main", authorization.RoleEditor)
	h.reader = humanCredentialPrincipal("usr_reader", "spc_main", authorization.RoleReader)
	h.other = humanCredentialPrincipal("usr_other", "spc_other", authorization.RoleReader)
	h.agent = Principal{
		Agent: &authorization.AgentPrincipal{
			AgentID: "agt_writer",
			Grants: []authorization.Grant{{
				SpaceID: "spc_main",
				Scopes: map[authorization.Scope]struct{}{
					authorization.ScopeCredentialList:   {},
					authorization.ScopeCredentialRead:   {},
					authorization.ScopeCredentialCreate: {},
					authorization.ScopeCredentialUpdate: {},
					authorization.ScopeCredentialDelete: {},
				},
			}},
		},
		Actor:     audit.Actor{Type: audit.ActorAgent, ID: "agt_writer", Fingerprint: "0123456789abcdef"},
		RequestID: "req_agent",
		SourceIP:  "127.0.0.1",
		UserAgent: "credential-test",
	}
	return h
}

func humanCredentialPrincipal(
	userID, spaceID string,
	role authorization.Role,
) Principal {
	return Principal{
		Human: &authorization.HumanPrincipal{
			Session:    identitySession(userID),
			SpaceRoles: map[string]authorization.Role{spaceID: role},
		},
		Actor:     audit.Actor{Type: audit.ActorUser, ID: userID, Fingerprint: "fedcba9876543210"},
		RequestID: "req_" + userID,
		SourceIP:  "127.0.0.1",
		UserAgent: "credential-test",
	}
}

func identitySession(userID string) identity.SessionPrincipal {
	return identity.SessionPrincipal{UserID: userID, SessionID: "ses_" + userID}
}

func (h *credentialHarness) createInput() CreateInput {
	return CreateInput{
		SpaceID: "spc_main", DisplayName: "Production login", Type: TypeLogin,
		Tags: map[string]string{"environment": "prod"}, Payload: json.RawMessage(
			`{"url":"https://example.test","username":"alice","password":"fixture-password"}`,
		),
	}
}

func (h *credentialHarness) writeContext(key string, actor audit.Actor) WriteContext {
	return WriteContext{Actor: actor, IdempotencyKey: key, Reason: "test mutation"}
}

func (h *credentialHarness) create(principal Principal) Metadata {
	h.t.Helper()
	created, err := h.service.Create(
		h.ctx, principal, h.createInput(), h.writeContext("idem-create", principal.Actor),
	)
	if err != nil {
		h.t.Fatal(err)
	}
	return created
}

func (h *credentialHarness) countCredentials() int {
	h.t.Helper()
	var count int
	if err := h.db.Reader.QueryRowContext(
		h.ctx, `SELECT count(*) FROM credentials`,
	).Scan(&count); err != nil {
		h.t.Fatal(err)
	}
	return count
}

func TestListNeverReturnsPayload(t *testing.T) {
	h := newCredentialHarness(t)
	h.create(h.editor)
	rows, _, err := h.service.List(h.ctx, h.reader, ListFilter{SpaceID: h.spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
	if _, exists := reflect.TypeOf(rows[0]).FieldByName("Payload"); exists {
		t.Fatal("metadata exposes payload")
	}
}

func TestCreateEncryptsPayloadAndCommitsAuditAtomically(t *testing.T) {
	h := newCredentialHarness(t)
	h.audit.FailNextInsert(audit.ErrAuditUnavailable)
	_, err := h.service.Create(
		h.ctx, h.editor, h.createInput(),
		h.writeContext("idem-audit-fail", h.editor.Actor),
	)
	if !errors.Is(err, ErrAuditUnavailable) || h.countCredentials() != 0 {
		t.Fatalf("err=%v rows=%d", err, h.countCredentials())
	}
}

func TestUpdateRequiresExpectedVersion(t *testing.T) {
	h := newCredentialHarness(t)
	created := h.create(h.editor)
	name := "Changed"
	_, err := h.service.Update(
		h.ctx,
		h.editor,
		UpdateInput{CredentialID: created.ID, ExpectedVersion: 0, DisplayName: &name},
		h.writeContext("idem-update-zero", h.editor.Actor),
	)
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("got %v", err)
	}
}

func TestAgentDeleteIsIdempotentSoftDelete(t *testing.T) {
	h := newCredentialHarness(t)
	created := h.create(h.editor)
	wc := h.writeContext("idem-delete", h.agent.Actor)
	if err := h.service.Delete(h.ctx, h.agent, created.ID, created.Version, wc); err != nil {
		t.Fatal(err)
	}
	if err := h.service.Delete(h.ctx, h.agent, created.ID, created.Version, wc); err != nil {
		t.Fatal(err)
	}
	var deletedAt sql.NullString
	if err := h.db.Reader.QueryRowContext(
		h.ctx, `SELECT deleted_at FROM credentials WHERE id = ?`, created.ID,
	).Scan(&deletedAt); err != nil {
		t.Fatal(err)
	}
	if !deletedAt.Valid {
		t.Fatal("credential was not soft deleted")
	}
}

func TestAgentUpdateReturnsOriginalIdempotentResult(t *testing.T) {
	h := newCredentialHarness(t)
	created := h.create(h.editor)
	name := "Updated by agent"
	input := UpdateInput{
		CredentialID: created.ID, ExpectedVersion: created.Version,
		DisplayName: &name,
	}
	wc := h.writeContext("idem-agent-update", h.agent.Actor)
	first, err := h.service.Update(h.ctx, h.agent, input, wc)
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.service.Update(h.ctx, h.agent, input, wc)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || first.Version != second.Version {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	var versions int
	if err := h.db.Reader.QueryRowContext(
		h.ctx,
		`SELECT count(*) FROM credential_versions WHERE credential_id = ?`,
		created.ID,
	).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 2 {
		t.Fatalf("versions=%d", versions)
	}
}

func TestCrossSpaceGetReturnsConcealedNotFound(t *testing.T) {
	h := newCredentialHarness(t)
	created := h.create(h.editor)
	_, err := h.service.Get(h.ctx, h.other, created.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestCrossSpaceListReturnsConcealedNotFound(t *testing.T) {
	h := newCredentialHarness(t)
	_, _, err := h.service.List(
		h.ctx, h.agent, ListFilter{SpaceID: h.otherSpace},
	)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestGetDoesNotReturnPayloadWhenAuditFails(t *testing.T) {
	h := newCredentialHarness(t)
	created := h.create(h.editor)
	h.audit.FailNextInsert(audit.ErrAuditUnavailable)
	got, err := h.service.Get(h.ctx, h.reader, created.ID)
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("got err %v", err)
	}
	if got.Payload != nil {
		t.Fatalf("payload returned after failed audit: %q", got.Payload)
	}
}

func TestOnlyOneConcurrentUpdateWins(t *testing.T) {
	h := newCredentialHarness(t)
	created := h.create(h.editor)
	start := make(chan struct{})
	errs := make(chan error, 2)
	for index := 0; index < 2; index++ {
		index := index
		go func() {
			<-start
			name := "Changed " + string(rune('A'+index))
			_, err := h.service.Update(
				h.ctx,
				h.editor,
				UpdateInput{
					CredentialID: created.ID, ExpectedVersion: created.Version,
					DisplayName: &name,
				},
				h.writeContext("idem-concurrent-"+name, h.editor.Actor),
			)
			errs <- err
		}()
	}
	close(start)
	var successes, conflicts int
	for range 2 {
		switch err := <-errs; {
		case err == nil:
			successes++
		case errors.Is(err, ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestPayloadAndIdempotencyRecordsDoNotContainPlaintext(t *testing.T) {
	h := newCredentialHarness(t)
	input := h.createInput()
	input.Payload = json.RawMessage(
		`{"engine":"postgres","host":"db.example.test","port":5432,"database":"app","username":"alice","password":"fixture-db-password","connection_string":"fixture-connection-string"}`,
	)
	input.Type = TypeDatabase
	_, err := h.service.Create(
		h.ctx, h.agent, input, h.writeContext("idem-agent-create", h.agent.Actor),
	)
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext, metadata []byte
	if err := h.db.Reader.QueryRowContext(
		h.ctx,
		`SELECT payload_ciphertext FROM credential_versions LIMIT 1`,
	).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if err := h.db.Reader.QueryRowContext(
		h.ctx,
		`SELECT COALESCE(response_headers, X'') FROM idempotency_records LIMIT 1`,
	).Scan(&metadata); err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range [][]byte{
		[]byte("fixture-db-password"), []byte("fixture-connection-string"),
	} {
		if bytes.Contains(ciphertext, sensitive) || bytes.Contains(metadata, sensitive) {
			t.Fatalf("plaintext leaked: %q", sensitive)
		}
	}
	if _, err := h.db.Writer.ExecContext(h.ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(h.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range [][]byte{
		[]byte("fixture-db-password"), []byte("fixture-connection-string"),
	} {
		if bytes.Contains(raw, sensitive) {
			t.Fatalf("plaintext leaked to database file: %q", sensitive)
		}
	}
}

func TestRestoreAndPurgeExpiredRecycleBin(t *testing.T) {
	h := newCredentialHarness(t)
	created := h.create(h.editor)
	if err := h.service.Delete(
		h.ctx, h.editor, created.ID, created.Version,
		h.writeContext("idem-delete-human", h.editor.Actor),
	); err != nil {
		t.Fatal(err)
	}
	owner := humanCredentialPrincipal("usr_editor", "spc_main", authorization.RoleOwner)
	if _, err := h.service.Restore(
		h.ctx, owner, created.ID, created.Version,
		h.writeContext("idem-restore", owner.Actor),
	); err != nil {
		t.Fatal(err)
	}
	err := h.service.Delete(
		h.ctx, h.editor, created.ID, created.Version,
		h.writeContext("idem-delete-again", h.editor.Actor),
	)
	if err != nil {
		t.Fatal(err)
	}
	h.clock.now = h.clock.now.Add(30 * 24 * time.Hour)
	systemOwner := humanCredentialPrincipal(
		"usr_editor", "spc_main", authorization.RoleOwner,
	)
	systemOwner.Human.SystemRole = identity.SystemRoleOwner
	count, err := h.service.PurgeExpired(h.ctx, systemOwner, h.spaceID)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("purged=%d", count)
	}
	if h.countCredentials() != 0 {
		t.Fatal("expired credential remains")
	}
}
