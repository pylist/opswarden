package agents

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/identity"
	"opswarden/internal/storage"
)

type testClock struct{ now time.Time }

func (clock *testClock) Now() time.Time { return clock.now }

type testAudit struct {
	fail bool
	seen []audit.Event
}

func (writer *testAudit) AppendTx(_ context.Context, _ *sql.Tx, event audit.Event) error {
	if writer.fail {
		return audit.ErrAuditUnavailable
	}
	writer.seen = append(writer.seen, event)
	return nil
}

type agentHarness struct {
	ctx     context.Context
	db      *storage.DB
	service *Service
	clock   *testClock
	audit   *testAudit
	owner   MutationContext
	member  MutationContext
	spaceID string
}

func newAgentHarness(t *testing.T) *agentHarness {
	t.Helper()
	db, err := storage.Open(t.TempDir() + "/agents.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	for _, row := range []struct {
		id, role string
	}{
		{"usr_owner", identity.SystemRoleOwner},
		{"usr_member", identity.SystemRoleMember},
	} {
		if _, err := db.Writer.Exec(`
			INSERT INTO users (
				id, email, normalized_email, password_hash, system_role,
				created_at, updated_at
			) VALUES (?, ?, ?, X'01', ?, ?, ?)
		`, row.id, row.id+"@example.test", row.id+"@example.test", row.role,
			formatAgentTime(now), formatAgentTime(now)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Writer.Exec(`
		INSERT INTO spaces (id, name, created_at, updated_at)
		VALUES ('spc_agents', 'Agents', ?, ?)
	`, formatAgentTime(now), formatAgentTime(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer.Exec(`
		INSERT INTO space_memberships (space_id, user_id, role, created_at)
		VALUES ('spc_agents', 'usr_member', 'owner', ?)
	`, formatAgentTime(now)); err != nil {
		t.Fatal(err)
	}
	clock := &testClock{now: now}
	auditWriter := &testAudit{}
	service, err := NewService(db, auditWriter, clock)
	if err != nil {
		t.Fatal(err)
	}
	return &agentHarness{
		ctx: context.Background(), db: db, service: service, clock: clock,
		audit: auditWriter, spaceID: "spc_agents",
		owner:  mutationContext("usr_owner"),
		member: mutationContext("usr_member"),
	}
}

func mutationContext(userID string) MutationContext {
	return MutationContext{
		Session: identity.SessionPrincipal{UserID: userID, SessionID: "ses_" + userID},
		Actor: audit.Actor{
			Type: audit.ActorUser, ID: userID, Fingerprint: "0123456789abcdef",
		},
		RequestID: "req_" + userID,
		SourceIP:  "127.0.0.1",
		UserAgent: "agent-service-test",
	}
}

func (h *agentHarness) createAgent(t *testing.T) Agent {
	t.Helper()
	agent, err := h.service.Create(h.ctx, h.owner, CreateInput{Name: "Hermes"})
	if err != nil {
		t.Fatal(err)
	}
	return agent
}

func TestTokenShownOnceAndStoredHashed(t *testing.T) {
	h := newAgentHarness(t)
	agent := h.createAgent(t)
	issued, err := h.service.IssueToken(
		h.ctx, h.owner, agent.ID, h.clock.now.Add(24*time.Hour),
	)
	if err != nil || issued.Raw == "" {
		t.Fatalf("issued=%+v err=%v", issued, err)
	}
	if !strings.HasPrefix(issued.Raw, "owat_") || len(issued.Raw) != len("owat_")+43 {
		t.Fatalf("unexpected token shape")
	}
	var storedHash []byte
	var storedPrefix string
	if err := h.db.Reader.QueryRow(
		`SELECT token_hash, token_prefix FROM agent_tokens WHERE id = ?`,
		issued.ID,
	).Scan(&storedHash, &storedPrefix); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(issued.Raw))
	if string(storedHash) != string(want[:]) || storedPrefix != issued.Prefix {
		t.Fatalf("token was not stored as hash plus prefix")
	}
	var rawColumns int
	if err := h.db.Reader.QueryRow(`
		SELECT count(*) FROM pragma_table_info('agent_tokens')
		WHERE lower(name) IN ('raw', 'token', 'raw_token')
	`).Scan(&rawColumns); err != nil {
		t.Fatal(err)
	}
	if rawColumns != 0 {
		t.Fatal("agent_tokens has a raw token column")
	}
}

func TestRevocationAndAgentDisableTakeEffectOnNextRequest(t *testing.T) {
	h := newAgentHarness(t)
	agent := h.createAgent(t)
	issued, err := h.service.IssueToken(
		h.ctx, h.owner, agent.ID, h.clock.now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Authenticate(h.ctx, issued.Raw); err != nil {
		t.Fatal(err)
	}
	if err := h.service.RevokeToken(h.ctx, h.owner, issued.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Authenticate(h.ctx, issued.Raw); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("got %v", err)
	}

	issued, err = h.service.IssueToken(
		h.ctx, h.owner, agent.ID, h.clock.now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Writer.Exec(
		`UPDATE agents SET deleted_at = ? WHERE id = ?`,
		formatAgentTime(h.clock.now), agent.ID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Authenticate(h.ctx, issued.Raw); !errors.Is(err, ErrAgentDisabled) {
		t.Fatalf("got %v", err)
	}
}

func TestExpiredTokenBoundaryFails(t *testing.T) {
	h := newAgentHarness(t)
	agent := h.createAgent(t)
	expiry := h.clock.now.Add(time.Hour)
	issued, err := h.service.IssueToken(h.ctx, h.owner, agent.ID, expiry)
	if err != nil {
		t.Fatal(err)
	}
	h.clock.now = expiry
	if _, err := h.service.Authenticate(h.ctx, issued.Raw); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("got %v", err)
	}
}

func TestGrantValidationAndFreshAuthentication(t *testing.T) {
	h := newAgentHarness(t)
	agent := h.createAgent(t)
	issued, err := h.service.IssueToken(
		h.ctx, h.owner, agent.ID, h.clock.now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	err = h.service.SetGrant(h.ctx, h.member, agent.ID, Grant{
		SpaceID: h.spaceID,
		Scopes:  []authorization.Scope{"root"},
	})
	if !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("got %v", err)
	}
	grant := Grant{
		SpaceID: h.spaceID,
		Scopes: []authorization.Scope{
			authorization.ScopeCredentialRead,
			authorization.ScopeCredentialList,
			authorization.ScopeCredentialRead,
		},
		RequiredLabels: map[string]string{"environment": "dev"},
	}
	if err := h.service.SetGrant(h.ctx, h.member, agent.ID, grant); err != nil {
		t.Fatal(err)
	}
	principal, err := h.service.Authenticate(h.ctx, issued.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(principal.Grants) != 1 ||
		len(principal.Grants[0].Scopes) != 2 ||
		principal.Grants[0].Scopes[0] != authorization.ScopeCredentialList {
		t.Fatalf("grant not canonicalized: %+v", principal.Grants)
	}
	if err := h.service.SetGrant(h.ctx, h.member, agent.ID, Grant{
		SpaceID: h.spaceID,
		Scopes:  []authorization.Scope{authorization.ScopeAssetRead},
	}); err != nil {
		t.Fatal(err)
	}
	principal, err = h.service.Authenticate(h.ctx, issued.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(principal.Grants[0].Scopes) != 1 ||
		principal.Grants[0].Scopes[0] != authorization.ScopeAssetRead {
		t.Fatalf("authentication reused stale grants: %+v", principal.Grants)
	}
}

func TestMutationAuthorizationAndAuditAreAtomic(t *testing.T) {
	h := newAgentHarness(t)
	if _, err := h.service.Create(
		h.ctx, h.member, CreateInput{Name: "Denied"},
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("got %v", err)
	}
	h.audit.fail = true
	if _, err := h.service.Create(
		h.ctx, h.owner, CreateInput{Name: "Rollback"},
	); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("got %v", err)
	}
	var count int
	if err := h.db.Reader.QueryRow(`SELECT count(*) FROM agents`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("mutation escaped failed audit: %d", count)
	}
}

func TestTokenAndGrantMutationsRollbackWithAudit(t *testing.T) {
	h := newAgentHarness(t)
	agent := h.createAgent(t)
	issued, err := h.service.IssueToken(
		h.ctx, h.owner, agent.ID, h.clock.now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}

	h.audit.fail = true
	failedIssue, err := h.service.IssueToken(
		h.ctx, h.owner, agent.ID, h.clock.now.Add(time.Hour),
	)
	if !errors.Is(err, ErrAuditUnavailable) || failedIssue.Raw != "" {
		t.Fatalf("issued=%+v err=%v", failedIssue, err)
	}
	var tokenCount int
	if err := h.db.Reader.QueryRow(`
		SELECT count(*) FROM agent_tokens WHERE agent_id = ?
	`, agent.ID).Scan(&tokenCount); err != nil {
		t.Fatal(err)
	}
	if tokenCount != 1 {
		t.Fatalf("token insert escaped failed audit: %d", tokenCount)
	}

	if err := h.service.SetGrant(h.ctx, h.member, agent.ID, Grant{
		SpaceID: h.spaceID,
		Scopes:  []authorization.Scope{authorization.ScopeCredentialRead},
	}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("set grant: %v", err)
	}
	var grantCount int
	if err := h.db.Reader.QueryRow(`
		SELECT count(*) FROM agent_space_grants WHERE agent_id = ?
	`, agent.ID).Scan(&grantCount); err != nil {
		t.Fatal(err)
	}
	if grantCount != 0 {
		t.Fatalf("grant escaped failed audit: %d", grantCount)
	}

	if err := h.service.RevokeToken(
		h.ctx, h.owner, issued.ID,
	); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("revoke token: %v", err)
	}
	h.audit.fail = false
	if _, err := h.service.Authenticate(h.ctx, issued.Raw); err != nil {
		t.Fatalf("revoke escaped failed audit: %v", err)
	}
}

func TestTokenPrefixCannotAuthenticate(t *testing.T) {
	h := newAgentHarness(t)
	agent := h.createAgent(t)
	issued, err := h.service.IssueToken(
		h.ctx, h.owner, agent.ID, h.clock.now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Authenticate(h.ctx, issued.Prefix); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v", err)
	}
}
