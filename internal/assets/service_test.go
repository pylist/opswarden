package assets

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/credentials"
	"opswarden/internal/identity"
	"opswarden/internal/storage"
)

type assetTestClock struct{ now time.Time }

func (c *assetTestClock) Now() time.Time { return c.now }

type assetAuditAppender struct {
	mu       sync.Mutex
	nextErr  error
	delegate *audit.Repository
}

func (a *assetAuditAppender) AppendTx(
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

func (a *assetAuditAppender) FailNext(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nextErr = err
}

type assetHarness struct {
	t                      *testing.T
	ctx                    context.Context
	db                     *storage.DB
	service                *Service
	audit                  *assetAuditAppender
	spaceID                string
	otherSpaceID           string
	assetID                string
	otherSpaceCredentialID string
	allowedDisplayName     string
	owner                  Principal
	reader                 Principal
	agent                  Principal
	labelScopedAgent       Principal
}

func newAssetHarness(t *testing.T) *assetHarness {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "opswarden.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	_, err = db.Writer.ExecContext(ctx, `
		INSERT INTO users (id, email, normalized_email, password_hash, system_role)
		VALUES
		  ('usr_owner', 'owner@example.test', 'owner@example.test', X'01', 'member'),
		  ('usr_reader', 'reader@example.test', 'reader@example.test', X'01', 'member');
		INSERT INTO spaces (id, name) VALUES
		  ('spc_main', 'Main'),
		  ('spc_other', 'Other');
		INSERT INTO space_memberships (space_id, user_id, role) VALUES
		  ('spc_main', 'usr_owner', 'owner'),
		  ('spc_main', 'usr_reader', 'reader');
		INSERT INTO agents (id, name, created_by_user_id)
		VALUES ('agt_assets', 'Asset reader', 'usr_owner');
		INSERT INTO credentials (id, space_id, name, type, current_version)
		VALUES
		  ('crd_allowed', 'spc_main', 'Allowed login', 'login', 1),
		  ('crd_denied', 'spc_main', 'Denied login', 'login', 1),
		  ('crd_other', 'spc_other', 'Other login', 'login', 1);
		INSERT INTO credential_tags (credential_id, tag) VALUES
		  ('crd_allowed', '["environment","prod"]'),
		  ('crd_denied', '["environment","dev"]');
	`)
	if err != nil {
		t.Fatal(err)
	}
	auditRepository, err := audit.NewRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	appender := &assetAuditAppender{delegate: auditRepository}
	clock := &assetTestClock{
		now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
	}
	service, err := NewService(db, appender, clock)
	if err != nil {
		t.Fatal(err)
	}
	h := &assetHarness{
		t: t, ctx: ctx, db: db, service: service, audit: appender,
		spaceID: "spc_main", otherSpaceID: "spc_other",
		otherSpaceCredentialID: "crd_other",
		allowedDisplayName:     "Allowed login",
	}
	h.owner = humanAssetPrincipal("usr_owner", "spc_main", authorization.RoleOwner)
	h.reader = humanAssetPrincipal("usr_reader", "spc_main", authorization.RoleReader)
	h.agent = agentAssetPrincipal(nil)
	h.labelScopedAgent = agentAssetPrincipal(map[string]string{"environment": "prod"})
	created, err := service.Create(ctx, h.owner, h.createInput())
	if err != nil {
		t.Fatal(err)
	}
	h.assetID = created.ID
	return h
}

func humanAssetPrincipal(
	userID, spaceID string,
	role authorization.Role,
) Principal {
	return Principal{
		Human: &authorization.HumanPrincipal{
			Session: identity.SessionPrincipal{
				UserID: userID, SessionID: "ses_" + userID,
			},
			SpaceRoles: map[string]authorization.Role{spaceID: role},
		},
		Actor: audit.Actor{
			Type: audit.ActorUser, ID: userID, Fingerprint: "0123456789abcdef",
		},
		RequestID: "req_" + userID,
		SourceIP:  "127.0.0.1",
		UserAgent: "asset-test",
	}
}

func agentAssetPrincipal(labels map[string]string) Principal {
	grants := []authorization.Grant{{
		SpaceID: "spc_main",
		Scopes: map[authorization.Scope]struct{}{
			authorization.ScopeAssetList: {},
			authorization.ScopeAssetRead: {},
		},
	}}
	grants = append(grants, authorization.Grant{
		SpaceID: "spc_main",
		Scopes: map[authorization.Scope]struct{}{
			authorization.ScopeCredentialList: {},
		},
		Labels: labels,
	})
	return Principal{
		Agent: &authorization.AgentPrincipal{
			AgentID: "agt_assets",
			Grants:  grants,
		},
		Actor: audit.Actor{
			Type: audit.ActorAgent, ID: "agt_assets", Fingerprint: "fedcba9876543210",
		},
		RequestID: "req_agent",
		SourceIP:  "127.0.0.1",
		UserAgent: "asset-test",
	}
}

func (h *assetHarness) createInput() CreateInput {
	return CreateInput{
		SpaceID:     "spc_main",
		Name:        "Production host",
		Type:        "server",
		Hostname:    "prod-1.example.test",
		OS:          "Linux",
		Environment: "production",
		Status:      "active",
		IPs:         []netip.Addr{netip.MustParseAddr("10.0.0.10")},
		Ports:       []uint16{22, 443},
		Tags:        map[string]string{"tier": "critical"},
		Notes:       "Primary application host",
	}
}

func (h *assetHarness) updateInput() UpdateInput {
	return UpdateInput{
		AssetID: h.assetID, ExpectedVersion: 1,
		Name: "Production host 2", Type: "server",
		Hostname: "prod-2.example.test", OS: "Linux",
		Environment: "production", Status: "maintenance",
		IPs:   []netip.Addr{netip.MustParseAddr("10.0.0.11")},
		Ports: []uint16{22}, Tags: map[string]string{"tier": "critical"},
		Notes: "Maintenance",
	}
}

func TestCannotLinkAcrossSpaces(t *testing.T) {
	h := newAssetHarness(t)
	err := h.service.LinkCredential(
		h.ctx, h.owner, h.assetID, h.otherSpaceCredentialID,
	)
	if !errors.Is(err, ErrCrossSpaceLink) {
		t.Fatalf("got %v", err)
	}
}

func TestCreateAcceptsEmptyOptionalCollections(t *testing.T) {
	h := newAssetHarness(t)
	input := h.createInput()
	input.Name = "Minimal asset"
	input.Hostname = "minimal.example.test"
	input.OS = ""
	input.Status = ""
	input.IPs = []netip.Addr{}
	input.Ports = []uint16{}
	input.Tags = map[string]string{}
	input.Notes = ""

	created, err := h.service.Create(h.ctx, h.owner, input)
	if err != nil {
		t.Fatalf("create minimal asset: %v", err)
	}
	if created.IPs == nil || created.Ports == nil {
		t.Fatalf("empty collections must remain JSON arrays: %#v", created)
	}
	update := UpdateInput{
		AssetID: created.ID, ExpectedVersion: created.Version,
		Name: "Minimal asset updated", Type: created.Type,
		Hostname: created.Hostname, Environment: created.Environment,
		IPs: []netip.Addr{}, Ports: []uint16{}, Tags: map[string]string{},
	}
	updated, err := h.service.Update(h.ctx, h.owner, update)
	if err != nil {
		t.Fatalf("update minimal asset: %v", err)
	}
	if updated.Version != 2 || updated.IPs == nil || updated.Ports == nil ||
		len(updated.Ports) != 0 {
		t.Fatalf("unexpected asset: %#v", updated)
	}
}

func TestAgentCannotMutateAsset(t *testing.T) {
	h := newAssetHarness(t)
	_, err := h.service.Update(h.ctx, h.agent, h.updateInput())
	if !errors.Is(err, authorization.ErrDenied) {
		t.Fatalf("got %v", err)
	}
}

func TestAssetListsOnlyAuthorizedCredentialMetadata(t *testing.T) {
	h := newAssetHarness(t)
	if err := h.service.LinkCredential(
		h.ctx, h.owner, h.assetID, "crd_allowed",
	); err != nil {
		t.Fatal(err)
	}
	if err := h.service.LinkCredential(
		h.ctx, h.owner, h.assetID, "crd_denied",
	); err != nil {
		t.Fatal(err)
	}
	rows, _, err := h.service.ListCredentialMetadata(
		h.ctx, h.labelScopedAgent, h.assetID, CredentialListPage{Limit: 50},
	)
	if err != nil || len(rows) != 1 ||
		rows[0].DisplayName != h.allowedDisplayName {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	if _, exists := reflect.TypeOf(rows[0]).FieldByName("Payload"); exists {
		t.Fatal("asset credential listing exposes payload")
	}
}

func TestCreateGetListAndUpdateValidatedMetadata(t *testing.T) {
	h := newAssetHarness(t)
	got, err := h.service.Get(h.ctx, h.reader, h.assetID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 ||
		!reflect.DeepEqual(got.IPs, []netip.Addr{netip.MustParseAddr("10.0.0.10")}) ||
		!reflect.DeepEqual(got.Ports, []uint16{22, 443}) {
		t.Fatalf("unexpected created asset: %+v", got)
	}
	rows, _, err := h.service.List(
		h.ctx, h.reader, ListFilter{SpaceID: h.spaceID, Limit: 50},
	)
	if err != nil || len(rows) != 1 || rows[0].ID != h.assetID {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	updated, err := h.service.Update(h.ctx, h.owner, h.updateInput())
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version != 2 || updated.Status != "maintenance" {
		t.Fatalf("unexpected update: %+v", updated)
	}
	_, err = h.service.Update(h.ctx, h.owner, h.updateInput())
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale update got %v", err)
	}
}

func TestDeleteRequiresExpectedVersionAndIsSoft(t *testing.T) {
	h := newAssetHarness(t)
	if err := h.service.Delete(h.ctx, h.owner, h.assetID, 2); !errors.Is(
		err, ErrVersionConflict,
	) {
		t.Fatalf("wrong version got %v", err)
	}
	if err := h.service.Delete(h.ctx, h.owner, h.assetID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Get(h.ctx, h.reader, h.assetID); !errors.Is(
		err, ErrNotFound,
	) {
		t.Fatalf("deleted get got %v", err)
	}
	var deletedAt sql.NullString
	if err := h.db.Reader.QueryRowContext(
		h.ctx, `SELECT deleted_at FROM assets WHERE id = ?`, h.assetID,
	).Scan(&deletedAt); err != nil || !deletedAt.Valid {
		t.Fatalf("deleted_at=%v err=%v", deletedAt, err)
	}
}

func TestInvalidAddressPortAndDuplicateMetadataRejected(t *testing.T) {
	h := newAssetHarness(t)
	cases := []CreateInput{
		func() CreateInput {
			input := h.createInput()
			input.IPs = []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}
			return input
		}(),
		func() CreateInput {
			input := h.createInput()
			input.Ports = []uint16{0}
			return input
		}(),
		func() CreateInput {
			input := h.createInput()
			input.Ports = []uint16{22, 22}
			return input
		}(),
		func() CreateInput {
			input := h.createInput()
			input.Hostname = "bad host name"
			return input
		}(),
	}
	for _, input := range cases {
		if _, err := h.service.Create(h.ctx, h.owner, input); !errors.Is(
			err, ErrInvalidInput,
		) {
			t.Fatalf("input=%+v err=%v", input, err)
		}
	}
}

func TestMutationAndAuditAreAtomic(t *testing.T) {
	h := newAssetHarness(t)
	h.audit.FailNext(audit.ErrAuditUnavailable)
	input := h.createInput()
	input.Name = "Must roll back"
	_, err := h.service.Create(h.ctx, h.owner, input)
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("got %v", err)
	}
	var count int
	if err := h.db.Reader.QueryRowContext(
		h.ctx, `SELECT count(*) FROM assets WHERE name = 'Must roll back'`,
	).Scan(&count); err != nil || count != 0 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func TestAgentNeedsAssetScopeAndNeverMutates(t *testing.T) {
	h := newAssetHarness(t)
	noScopes := h.agent
	noScopes.Agent = &authorization.AgentPrincipal{
		AgentID: "agt_assets",
		Grants:  []authorization.Grant{{SpaceID: h.spaceID}},
	}
	if _, err := h.service.Get(h.ctx, noScopes, h.assetID); !errors.Is(
		err, ErrNotFound,
	) {
		t.Fatalf("unscoped get got %v", err)
	}
	if err := h.service.Delete(
		h.ctx, h.agent, h.assetID, 1,
	); !errors.Is(err, authorization.ErrDenied) {
		t.Fatalf("agent delete got %v", err)
	}
}

func TestDatabaseRejectsCrossSpaceCredentialLink(t *testing.T) {
	h := newAssetHarness(t)
	_, err := h.db.Writer.ExecContext(h.ctx, `
		INSERT INTO asset_credentials (space_id, asset_id, credential_id)
		VALUES (?, ?, ?)
	`, h.otherSpaceID, h.assetID, h.otherSpaceCredentialID)
	if err == nil {
		t.Fatal("database accepted a cross-Space credential link")
	}
}

func TestCredentialMetadataTypeRemainsMetadataOnly(t *testing.T) {
	var row credentials.Metadata
	if _, exists := reflect.TypeOf(row).FieldByName("Payload"); exists {
		t.Fatal("credentials.Metadata unexpectedly has payload")
	}
}

func TestReadsLegacyAssetRowsWithSQLiteDefaultTimestamps(t *testing.T) {
	h := newAssetHarness(t)
	if _, err := h.db.Writer.ExecContext(h.ctx, `
		INSERT INTO assets (id, space_id, name, type)
		VALUES ('ast_legacy', 'spc_main', 'Legacy host', 'server')
	`); err != nil {
		t.Fatal(err)
	}
	got, err := h.service.Get(h.ctx, h.reader, "ast_legacy")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || got.Name != "Legacy host" {
		t.Fatalf("legacy asset=%+v", got)
	}
}

func TestListScansPastUnauthorizedRowsBeforeApplyingPageLimit(t *testing.T) {
	h := newAssetHarness(t)
	insertAssets(t, h, 520, "denied")
	insertAsset(t, h, "ast_zzzz_allowed", "allowed")
	principal := scopedAssetAgent(map[string]string{"visibility": "allowed"})

	rows, next, err := h.service.List(
		h.ctx, principal, ListFilter{SpaceID: h.spaceID, Limit: 1},
	)
	if err != nil || len(rows) != 1 || rows[0].ID != "ast_zzzz_allowed" ||
		next != "" {
		t.Fatalf("rows=%+v next=%q err=%v", rows, next, err)
	}
}

func TestListReturnsContinuationWhenAuthorizationScanBudgetIsExhausted(
	t *testing.T,
) {
	h := newAssetHarness(t)
	insertAssets(t, h, maxListScan, "denied")
	insertAsset(t, h, "ast_zzzz_allowed", "allowed")
	principal := scopedAssetAgent(map[string]string{"visibility": "allowed"})

	rows, next, err := h.service.List(
		h.ctx, principal, ListFilter{SpaceID: h.spaceID, Limit: 1},
	)
	if err != nil || len(rows) != 0 || next == "" {
		t.Fatalf("first rows=%+v next=%q err=%v", rows, next, err)
	}
	rows, final, err := h.service.List(
		h.ctx, principal,
		ListFilter{SpaceID: h.spaceID, Limit: 1, After: next},
	)
	if err != nil || len(rows) != 1 || rows[0].ID != "ast_zzzz_allowed" ||
		final != "" {
		t.Fatalf("second rows=%+v next=%q err=%v", rows, final, err)
	}
}

func TestListCursorHasNoOmissionsDuplicatesAndIsBoundToFilter(t *testing.T) {
	h := newAssetHarness(t)
	for index := range 5 {
		insertAsset(
			t, h, fmt.Sprintf("ast_page_%02d", index), "allowed",
		)
	}
	principal := scopedAssetAgent(map[string]string{"visibility": "allowed"})
	filter := ListFilter{
		SpaceID: h.spaceID, Type: "server",
		Tags: map[string]string{"visibility": "allowed"}, Limit: 2,
	}
	var ids []string
	for {
		rows, next, err := h.service.List(h.ctx, principal, filter)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			ids = append(ids, row.ID)
		}
		if next == "" {
			break
		}
		filter.After = next
	}
	if len(ids) != 5 {
		t.Fatalf("ids=%v", ids)
	}
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("duplicate %q in %v", id, ids)
		}
		seen[id] = struct{}{}
	}

	first := ListFilter{
		SpaceID: h.spaceID, Type: "server",
		Tags: map[string]string{"visibility": "allowed"}, Limit: 1,
	}
	_, cursor, err := h.service.List(h.ctx, principal, first)
	if err != nil || cursor == "" {
		t.Fatalf("cursor=%q err=%v", cursor, err)
	}
	for name, changed := range map[string]ListFilter{
		"space": {
			SpaceID: h.otherSpaceID, Type: "server",
			Tags:  map[string]string{"visibility": "allowed"},
			Limit: 1, After: cursor,
		},
		"type": {
			SpaceID: h.spaceID, Type: "device",
			Tags:  map[string]string{"visibility": "allowed"},
			Limit: 1, After: cursor,
		},
		"canonical": {
			SpaceID: h.spaceID, Type: "server",
			Tags:  map[string]string{"visibility": "allowed"},
			Limit: 1, After: cursor + "=",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := h.service.List(
				h.ctx, principal, changed,
			); !errors.Is(err, ErrInvalidCursor) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestCredentialMetadataScansPastUnauthorizedPrefixAndPaginates(t *testing.T) {
	h := newAssetHarness(t)
	insertLinkedCredentials(t, h, 520, "dev")
	insertLinkedCredential(t, h, "crd_zzzz_allowed", "Allowed after prefix", "prod")

	page := CredentialListPage{Limit: 1}
	rows, next, err := h.service.ListCredentialMetadata(
		h.ctx, h.labelScopedAgent, h.assetID, page,
	)
	if err != nil || len(rows) != 1 ||
		rows[0].ID != "crd_zzzz_allowed" || next != "" {
		t.Fatalf("rows=%+v next=%q err=%v", rows, next, err)
	}

	insertLinkedCredential(t, h, "crd_zzzz_allowed_2", "Allowed two", "prod")
	rows, next, err = h.service.ListCredentialMetadata(
		h.ctx, h.labelScopedAgent, h.assetID, page,
	)
	if err != nil || len(rows) != 1 || next == "" {
		t.Fatalf("first rows=%+v next=%q err=%v", rows, next, err)
	}
	second, final, err := h.service.ListCredentialMetadata(
		h.ctx, h.labelScopedAgent, h.assetID,
		CredentialListPage{Limit: 1, After: next},
	)
	if err != nil || len(second) != 1 || final != "" ||
		second[0].ID == rows[0].ID {
		t.Fatalf("second=%+v next=%q err=%v", second, final, err)
	}
}

func TestCredentialMetadataReturnsContinuationAtScanBudget(t *testing.T) {
	h := newAssetHarness(t)
	insertLinkedCredentials(t, h, maxListScan, "dev")
	insertLinkedCredential(t, h, "crd_zzzz_allowed", "Allowed after budget", "prod")

	rows, next, err := h.service.ListCredentialMetadata(
		h.ctx, h.labelScopedAgent, h.assetID, CredentialListPage{Limit: 1},
	)
	if err != nil || len(rows) != 0 || next == "" {
		t.Fatalf("first rows=%+v next=%q err=%v", rows, next, err)
	}
	rows, final, err := h.service.ListCredentialMetadata(
		h.ctx, h.labelScopedAgent, h.assetID,
		CredentialListPage{Limit: 1, After: next},
	)
	if err != nil || len(rows) != 1 ||
		rows[0].ID != "crd_zzzz_allowed" || final != "" {
		t.Fatalf("second rows=%+v next=%q err=%v", rows, final, err)
	}
}

func TestCredentialCursorIsBoundToAssetAndSpace(t *testing.T) {
	h := newAssetHarness(t)
	insertLinkedCredential(t, h, "crd_cursor_1", "Cursor one", "prod")
	insertLinkedCredential(t, h, "crd_cursor_2", "Cursor two", "prod")
	_, cursor, err := h.service.ListCredentialMetadata(
		h.ctx, h.labelScopedAgent, h.assetID, CredentialListPage{Limit: 1},
	)
	if err != nil || cursor == "" {
		t.Fatalf("cursor=%q err=%v", cursor, err)
	}
	second, err := h.service.Create(h.ctx, h.owner, h.createInput())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.service.ListCredentialMetadata(
		h.ctx, h.labelScopedAgent, second.ID,
		CredentialListPage{Limit: 1, After: cursor},
	); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-asset cursor got %v", err)
	}
	if _, _, err := h.service.ListCredentialMetadata(
		h.ctx, h.labelScopedAgent, h.assetID,
		CredentialListPage{Limit: 1, After: cursor + "="},
	); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("noncanonical cursor got %v", err)
	}
}

func TestUnlinkRequiresActiveSameSpaceCredentialAndAuthorization(t *testing.T) {
	t.Run("soft deleted credential", func(t *testing.T) {
		h := newAssetHarness(t)
		if err := h.service.LinkCredential(
			h.ctx, h.owner, h.assetID, "crd_allowed",
		); err != nil {
			t.Fatal(err)
		}
		if _, err := h.db.Writer.ExecContext(h.ctx, `
			UPDATE credentials SET deleted_at = CURRENT_TIMESTAMP
			WHERE id = 'crd_allowed'
		`); err != nil {
			t.Fatal(err)
		}
		if err := h.service.UnlinkCredential(
			h.ctx, h.owner, h.assetID, "crd_allowed",
		); !errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("reader denied", func(t *testing.T) {
		h := newAssetHarness(t)
		if err := h.service.UnlinkCredential(
			h.ctx, h.reader, h.assetID, "crd_allowed",
		); !errors.Is(err, authorization.ErrDenied) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("cross Space", func(t *testing.T) {
		h := newAssetHarness(t)
		if err := h.service.UnlinkCredential(
			h.ctx, h.owner, h.assetID, h.otherSpaceCredentialID,
		); !errors.Is(err, ErrCrossSpaceLink) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestUnlinkAuditFailureRollsBackRelationship(t *testing.T) {
	h := newAssetHarness(t)
	if err := h.service.LinkCredential(
		h.ctx, h.owner, h.assetID, "crd_allowed",
	); err != nil {
		t.Fatal(err)
	}
	h.audit.FailNext(audit.ErrAuditUnavailable)
	if err := h.service.UnlinkCredential(
		h.ctx, h.owner, h.assetID, "crd_allowed",
	); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("got %v", err)
	}
	var count int
	if err := h.db.Reader.QueryRowContext(h.ctx, `
		SELECT count(*) FROM asset_credentials
		WHERE asset_id = ? AND credential_id = 'crd_allowed'
	`, h.assetID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func TestStorageFailuresReturnStableDomainError(t *testing.T) {
	t.Run("closed database", func(t *testing.T) {
		h := newAssetHarness(t)
		if err := h.db.Close(); err != nil {
			t.Fatal(err)
		}
		_, _, err := h.service.List(
			h.ctx, h.reader, ListFilter{SpaceID: h.spaceID},
		)
		if !errors.Is(err, ErrUnavailable) ||
			strings.Contains(strings.ToLower(err.Error()), "database") {
			t.Fatalf("got %q", err)
		}
	})

	t.Run("constraint trigger", func(t *testing.T) {
		h := newAssetHarness(t)
		if _, err := h.db.Writer.ExecContext(h.ctx, `
			CREATE TRIGGER reject_asset_insert
			BEFORE INSERT ON assets
			BEGIN
				SELECT RAISE(ABORT, 'SENSITIVE assets constraint detail');
			END
		`); err != nil {
			t.Fatal(err)
		}
		input := h.createInput()
		input.Name = "Rejected"
		_, err := h.service.Create(h.ctx, h.owner, input)
		if !errors.Is(err, ErrUnavailable) ||
			strings.Contains(err.Error(), "SENSITIVE") ||
			strings.Contains(strings.ToLower(err.Error()), "insert") {
			t.Fatalf("got %q", err)
		}
	})
}

func scopedAssetAgent(labels map[string]string) Principal {
	principal := agentAssetPrincipal(nil)
	principal.Agent.Grants[0].Labels = labels
	return principal
}

func insertAssets(t *testing.T, h *assetHarness, count int, visibility string) {
	t.Helper()
	tx, err := h.db.Writer.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for index := range count {
		id := fmt.Sprintf("ast_scan_%05d", index)
		insertAssetTx(t, h.ctx, tx, id, visibility)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func insertAsset(t *testing.T, h *assetHarness, id, visibility string) {
	t.Helper()
	tx, err := h.db.Writer.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	insertAssetTx(t, h.ctx, tx, id, visibility)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func insertAssetTx(
	t *testing.T,
	ctx context.Context,
	tx *sql.Tx,
	id, visibility string,
) {
	t.Helper()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO assets (id, space_id, name, type)
		VALUES (?, 'spc_main', ?, 'server')
	`, id, id); err != nil {
		t.Fatal(err)
	}
	tag, err := encodeTag("visibility", visibility)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO asset_tags (asset_id, tag) VALUES (?, ?)
	`, id, tag); err != nil {
		t.Fatal(err)
	}
}

func insertLinkedCredentials(
	t *testing.T,
	h *assetHarness,
	count int,
	environment string,
) {
	t.Helper()
	tx, err := h.db.Writer.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for index := range count {
		id := fmt.Sprintf("crd_scan_%05d", index)
		insertLinkedCredentialTx(
			t, h.ctx, tx, h.assetID, id, id, environment,
		)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func insertLinkedCredential(
	t *testing.T,
	h *assetHarness,
	id, name, environment string,
) {
	t.Helper()
	tx, err := h.db.Writer.BeginTx(h.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	insertLinkedCredentialTx(
		t, h.ctx, tx, h.assetID, id, name, environment,
	)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func insertLinkedCredentialTx(
	t *testing.T,
	ctx context.Context,
	tx *sql.Tx,
	assetID, id, name, environment string,
) {
	t.Helper()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO credentials (id, space_id, name, type, current_version)
		VALUES (?, 'spc_main', ?, 'login', 1)
	`, id, name); err != nil {
		t.Fatal(err)
	}
	tag, err := encodeTag("environment", environment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO credential_tags (credential_id, tag) VALUES (?, ?)
	`, id, tag); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO asset_credentials (space_id, asset_id, credential_id)
		VALUES ('spc_main', ?, ?)
	`, assetID, id); err != nil {
		t.Fatal(err)
	}
}
