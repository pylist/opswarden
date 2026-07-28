package agents

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
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
		Session: identity.SessionPrincipal{
			UserID: userID, SessionID: "ses_" + userID,
			RecentTOTPAt: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
		},
		Actor: audit.Actor{
			Type: audit.ActorUser, ID: userID, Fingerprint: "0123456789abcdef",
		},
		RequestID:      "req_" + userID,
		SourceIP:       "127.0.0.1",
		UserAgent:      "agent-service-test",
		IdempotencyKey: "default-key-" + userID,
	}
}

func TestSetGrantRequiresRecentTOTPInDomain(t *testing.T) {
	h := newAgentHarness(t)
	agent := h.createAgent(t)
	stolen := h.owner
	stolen.Session.RecentTOTPAt = h.clock.now.Add(-identity.RecentTOTPLifetime)
	err := h.service.SetGrant(h.ctx, stolen, agent.ID, Grant{
		SpaceID: h.spaceID,
		Scopes:  []authorization.Scope{authorization.ScopeCredentialList},
	})
	if !errors.Is(err, identity.ErrRecentTOTPRequired) {
		t.Fatalf("set grant error=%v", err)
	}
}

func TestAgentManagementMutationRequiresIdempotencyKeyInDomain(t *testing.T) {
	h := newAgentHarness(t)
	principal := h.owner
	principal.IdempotencyKey = ""
	if _, err := h.service.Create(
		h.ctx, principal, CreateInput{Name: "Hermes"},
	); !errors.Is(err, ErrIdempotencyRequired) {
		t.Fatalf("create error=%v", err)
	}
	var count int
	if err := h.db.Reader.QueryRowContext(
		h.ctx, `SELECT count(*) FROM agents`,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("agents created without idempotency key=%d", count)
	}
}

func TestHumanAgentCreateIdempotencyPersistsStableResult(t *testing.T) {
	h := newAgentHarness(t)
	principal := h.owner
	principal.IdempotencyKey = "create-agent-once"
	first, err := h.service.Create(h.ctx, principal, CreateInput{Name: "Hermes"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.service.Create(h.ctx, principal, CreateInput{Name: "Hermes"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("replay IDs=(%s,%s)", first.ID, second.ID)
	}
	_, err = h.service.Create(h.ctx, principal, CreateInput{Name: "Different"})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different request error=%v", err)
	}
}

func TestHumanAgentTokenIssueReplayNeverReturnsOrCreatesAnotherRawToken(t *testing.T) {
	h := newAgentHarness(t)
	agent := h.createAgent(t)
	principal := h.owner
	principal.IdempotencyKey = "issue-token-once"
	first, err := h.service.IssueToken(
		h.ctx, principal, agent.ID, h.clock.now.Add(time.Hour),
	)
	if err != nil || first.Raw == "" || first.Replayed {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	second, err := h.service.IssueToken(
		h.ctx, principal, agent.ID, h.clock.now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || second.Raw != "" || !second.Replayed {
		t.Fatalf("unsafe replay: first=%+v second=%+v", first, second)
	}
	var count int
	if err := h.db.Reader.QueryRow(
		`SELECT count(*) FROM agent_tokens WHERE agent_id = ?`, agent.ID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("issued tokens=%d", count)
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

	secondIssue := h.owner
	secondIssue.IdempotencyKey = "second-token"
	issued, err = h.service.IssueToken(
		h.ctx, secondIssue, agent.ID, h.clock.now.Add(time.Hour),
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
	secondGrant := h.member
	secondGrant.IdempotencyKey = "second-grant"
	if err := h.service.SetGrant(h.ctx, secondGrant, agent.ID, Grant{
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
	failedIssueContext := h.owner
	failedIssueContext.IdempotencyKey = "failed-issue"
	failedIssue, err := h.service.IssueToken(
		h.ctx, failedIssueContext, agent.ID, h.clock.now.Add(time.Hour),
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

func TestAuthenticationFailuresHaveOnePublicMessage(t *testing.T) {
	h := newAgentHarness(t)
	agent := h.createAgent(t)
	expired, err := h.service.IssueToken(
		h.ctx, h.owner, agent.ID, h.clock.now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	h.clock.now = h.clock.now.Add(time.Hour)
	_, expiredErr := h.service.Authenticate(h.ctx, expired.Raw)
	_, invalidErr := h.service.Authenticate(h.ctx, "not-a-token")
	if expiredErr == nil || invalidErr == nil ||
		expiredErr.Error() != invalidErr.Error() {
		t.Fatalf("expired=%q invalid=%q", expiredErr, invalidErr)
	}
	if !errors.Is(expiredErr, ErrTokenExpired) ||
		!errors.Is(expiredErr, ErrAuthenticationFailed) ||
		!errors.Is(invalidErr, ErrInvalidToken) ||
		!errors.Is(invalidErr, ErrAuthenticationFailed) {
		t.Fatalf("expired=%v invalid=%v", expiredErr, invalidErr)
	}
}

func TestAuthenticateFailsClosedOnClockRollbackWithoutRegressingUsage(t *testing.T) {
	h := newAgentHarness(t)
	agent := h.createAgent(t)
	issued, err := h.service.IssueToken(
		h.ctx, h.owner, agent.ID, h.clock.now.Add(24*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	firstUsedAt := h.clock.now.Add(time.Hour)
	h.clock.now = firstUsedAt
	if _, err := h.service.Authenticate(h.ctx, issued.Raw); err != nil {
		t.Fatal(err)
	}
	h.clock.now = firstUsedAt.Add(-time.Minute)
	if _, err := h.service.Authenticate(
		h.ctx, issued.Raw,
	); !errors.Is(err, ErrInvalidClock) {
		t.Fatalf("got %v", err)
	}
	var stored string
	if err := h.db.Reader.QueryRow(`
		SELECT last_used_at FROM agent_tokens WHERE id = ?
	`, issued.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != formatAgentTime(firstUsedAt) {
		t.Fatalf("last_used_at regressed to %q", stored)
	}
	h.clock.now = time.Time{}
	if _, err := h.service.Authenticate(
		h.ctx, issued.Raw,
	); !errors.Is(err, ErrInvalidClock) {
		t.Fatalf("zero clock: %v", err)
	}
}

func TestAuthenticateFailsClosedOnMalformedGrantShapes(t *testing.T) {
	for name, corruption := range map[string]struct {
		scopes string
		labels string
	}{
		"labels null": {
			scopes: `["credential:read"]`, labels: `null`,
		},
		"labels array": {
			scopes: `["credential:read"]`, labels: `[]`,
		},
		"labels scalar": {
			scopes: `["credential:read"]`, labels: `"dev"`,
		},
		"labels duplicate": {
			scopes: `["credential:read"]`,
			labels: `{"environment":"dev","environment":"dev"}`,
		},
		"labels noncanonical": {
			scopes: `["credential:read"]`, labels: `{ "environment":"dev"}`,
		},
		"labels invalid key": {
			scopes: `["credential:read"]`, labels: `{" Environment":"dev"}`,
		},
		"scopes null": {
			scopes: `null`, labels: `{}`,
		},
		"scopes object": {
			scopes: `{"scope":"credential:read"}`, labels: `{}`,
		},
		"scopes scalar": {
			scopes: `"credential:read"`, labels: `{}`,
		},
		"scopes duplicate": {
			scopes: `["credential:read","credential:read"]`, labels: `{}`,
		},
		"scopes wrong case": {
			scopes: `["Credential:Read"]`, labels: `{}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newAgentHarness(t)
			agent := h.createAgent(t)
			issued, err := h.service.IssueToken(
				h.ctx, h.owner, agent.ID, h.clock.now.Add(time.Hour),
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.db.Writer.Exec(`
				INSERT INTO agent_space_grants (
					agent_id, space_id, role, scopes_json, labels_json
				) VALUES (?, ?, 'scoped', ?, ?)
			`, agent.ID, h.spaceID, corruption.scopes, corruption.labels); err != nil {
				t.Fatal(err)
			}
			if _, err := h.service.Authenticate(
				h.ctx, issued.Raw,
			); !errors.Is(err, ErrAuthenticationUnavailable) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestAuthenticateRemainsCorrectWithManyNonmatchingTokens(t *testing.T) {
	h := newAgentHarness(t)
	agent := h.createAgent(t)
	target, err := h.service.IssueToken(
		h.ctx, h.owner, agent.ID, h.clock.now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2_000; index++ {
		hash := sha256.Sum256([]byte("nonmatching-" + strconv.Itoa(index)))
		if _, err := h.db.Writer.Exec(`
			INSERT INTO agent_tokens (
				id, agent_id, token_hash, token_prefix, created_at, expires_at
			) VALUES (?, ?, ?, 'owat_unused', ?, ?)
		`, "bulk_"+subjectForTest(index)+"_"+strings.Repeat("x", index/36),
			agent.ID, hash[:], formatAgentTime(h.clock.now),
			formatAgentTime(h.clock.now.Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.service.Authenticate(h.ctx, target.Raw); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentRevocationNeverAuthenticatesAfterCommit(t *testing.T) {
	h := newAgentHarness(t)
	agent := h.createAgent(t)
	issued, err := h.service.IssueToken(
		h.ctx, h.owner, agent.ID, h.clock.now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	revokeDone := make(chan struct{})
	errs := make(chan error, 8)
	for range 8 {
		go func() {
			<-start
			for {
				select {
				case <-revokeDone:
					for range 20 {
						if _, err := h.service.Authenticate(
							h.ctx, issued.Raw,
						); err == nil {
							errs <- errors.New("authenticated after revocation commit")
							return
						}
					}
					errs <- nil
					return
				default:
					_, _ = h.service.Authenticate(h.ctx, issued.Raw)
				}
			}
		}()
	}
	close(start)
	if err := h.service.RevokeToken(h.ctx, h.owner, issued.ID); err != nil {
		t.Fatal(err)
	}
	close(revokeDone)
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestMaximumCanonicalGrantSizeWritesAndAuthenticates(t *testing.T) {
	h := newAgentHarness(t)
	agent := h.createAgent(t)
	issued, err := h.service.IssueToken(
		h.ctx, h.owner, agent.ID, h.clock.now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	maximum, _ := grantJSONBoundary(t, h.spaceID)
	encoded, err := json.Marshal(maximum.RequiredLabels)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > maxGrantJSONBytes ||
		maxGrantJSONBytes-len(encoded) > 1 {
		t.Fatalf("labels size=%d limit=%d", len(encoded), maxGrantJSONBytes)
	}
	if err := h.service.SetGrant(
		h.ctx, h.member, agent.ID, maximum,
	); err != nil {
		t.Fatal(err)
	}
	principal, err := h.service.Authenticate(h.ctx, issued.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(principal.Grants) != 1 ||
		len(principal.Grants[0].RequiredLabels) !=
			len(maximum.RequiredLabels) {
		t.Fatalf("grant=%+v", principal.Grants)
	}
}

func TestOversizeCanonicalGrantRejectedWithoutReplacingOriginal(t *testing.T) {
	h := newAgentHarness(t)
	agent := h.createAgent(t)
	issued, err := h.service.IssueToken(
		h.ctx, h.owner, agent.ID, h.clock.now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	original := Grant{
		SpaceID: h.spaceID,
		Scopes:  []authorization.Scope{authorization.ScopeCredentialRead},
		RequiredLabels: map[string]string{
			"environment": "dev",
		},
	}
	if err := h.service.SetGrant(
		h.ctx, h.member, agent.ID, original,
	); err != nil {
		t.Fatal(err)
	}
	var scopesBefore, labelsBefore []byte
	if err := h.db.Reader.QueryRow(`
		SELECT scopes_json, labels_json
		FROM agent_space_grants
		WHERE agent_id = ? AND space_id = ?
	`, agent.ID, h.spaceID).Scan(&scopesBefore, &labelsBefore); err != nil {
		t.Fatal(err)
	}
	auditsBefore := len(h.audit.seen)
	_, oversize := grantJSONBoundary(t, h.spaceID)
	encoded, err := json.Marshal(oversize.RequiredLabels)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) <= maxGrantJSONBytes {
		t.Fatalf("oversize labels=%d", len(encoded))
	}
	if err := h.service.SetGrant(
		h.ctx, h.member, agent.ID, oversize,
	); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("got %v", err)
	}
	if len(h.audit.seen) != auditsBefore {
		t.Fatal("oversize grant emitted an audit event")
	}
	var scopesAfter, labelsAfter []byte
	if err := h.db.Reader.QueryRow(`
		SELECT scopes_json, labels_json
		FROM agent_space_grants
		WHERE agent_id = ? AND space_id = ?
	`, agent.ID, h.spaceID).Scan(&scopesAfter, &labelsAfter); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(scopesBefore, scopesAfter) ||
		!bytes.Equal(labelsBefore, labelsAfter) {
		t.Fatal("oversize grant replaced the original")
	}
	principal, err := h.service.Authenticate(h.ctx, issued.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(principal.Grants) != 1 ||
		principal.Grants[0].RequiredLabels["environment"] != "dev" {
		t.Fatalf("original grant changed: %+v", principal.Grants)
	}
}

func grantJSONBoundary(t *testing.T, spaceID string) (Grant, Grant) {
	t.Helper()
	labels := make(map[string]string, maxGrantLabels)
	for index := 0; index < maxGrantLabels; index++ {
		labels["label-"+strconv.Itoa(index)] = ""
	}
	for index := 0; index < maxGrantLabels; index++ {
		key := "label-" + strconv.Itoa(index)
		for len(labels[key]) < 512 {
			labels[key] += `\`
			encoded, err := json.Marshal(labels)
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) > maxGrantJSONBytes {
				oversizeLabels := cloneLabels(labels)
				labels[key] = strings.TrimSuffix(labels[key], `\`)
				return Grant{
						SpaceID: spaceID,
						Scopes: []authorization.Scope{
							authorization.ScopeCredentialRead,
						},
						RequiredLabels: cloneLabels(labels),
					}, Grant{
						SpaceID: spaceID,
						Scopes: []authorization.Scope{
							authorization.ScopeCredentialRead,
						},
						RequiredLabels: oversizeLabels,
					}
			}
		}
	}
	t.Fatal("could not construct grant JSON boundary")
	return Grant{}, Grant{}
}
