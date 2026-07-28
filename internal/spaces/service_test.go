package spaces_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"opswarden/internal/identity"
	"opswarden/internal/spaces"
	"opswarden/internal/storage"
)

var _ spaces.SessionRevoker = (*identity.Service)(nil)

func TestCreateMakesAuthenticatedPrincipalOwnerAndListUsesPrincipal(t *testing.T) {
	h := newSpacesHarness(t)

	created, err := h.service.Create(
		h.ctx,
		h.principal("owner"),
		spaces.CreateInput{Name: "  Production  "},
	)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Name != "Production" {
		t.Fatalf("created Space = %+v", created)
	}
	if role := h.membershipRole(t, created.ID, "owner"); role != spaces.Owner {
		t.Fatalf("creator role = %q, want Owner", role)
	}

	rows, err := h.service.ListForUser(h.ctx, h.principal("owner"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != created.ID {
		t.Fatalf("owner Spaces = %+v", rows)
	}
	rows, err = h.service.ListForUser(h.ctx, h.principal("member"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("unassigned member Spaces = %+v", rows)
	}
}

func TestServiceRejectsUnauthenticatedOrDeletedPrincipal(t *testing.T) {
	h := newSpacesHarness(t)
	if _, err := h.service.Create(
		h.ctx, identity.SessionPrincipal{}, spaces.CreateInput{Name: "Production"},
	); !errors.Is(err, spaces.ErrUnauthenticated) {
		t.Fatalf("empty principal error = %v", err)
	}

	deleted := h.principal("member")
	h.mustExec(`UPDATE users SET deleted_at = ? WHERE id = ?`, h.nowString(), "member")
	if _, err := h.service.Create(
		h.ctx, deleted, spaces.CreateInput{Name: "Production"},
	); !errors.Is(err, spaces.ErrUnauthenticated) {
		t.Fatalf("deleted principal error = %v", err)
	}
}

func TestOwnerManagesMembersWhileEditorCannot(t *testing.T) {
	h := newSpacesHarness(t)
	spaceID := h.createSpace(t, "owner")
	if err := h.service.AddMember(
		h.ctx, h.principal("owner"), spaceID, "editor", spaces.Editor,
	); err != nil {
		t.Fatal(err)
	}
	if role := h.membershipRole(t, spaceID, "editor"); role != spaces.Editor {
		t.Fatalf("editor role = %q", role)
	}

	err := h.service.AddMember(
		h.ctx, h.principal("editor"), spaceID, "member", spaces.Reader,
	)
	if !errors.Is(err, spaces.ErrForbidden) {
		t.Fatalf("editor AddMember error = %v", err)
	}
	if h.membershipExists(t, spaceID, "member") {
		t.Fatal("editor added member")
	}
}

func TestCrossSpaceMemberMutationReturnsConcealedNotFound(t *testing.T) {
	h := newSpacesHarness(t)
	spaceID := h.createSpace(t, "owner")
	otherSpaceID := h.createSpace(t, "member")

	err := h.service.AddMember(
		h.ctx, h.principal("owner"), otherSpaceID, "editor", spaces.Reader,
	)
	if !errors.Is(err, spaces.ErrNotFound) {
		t.Fatalf("cross-Space error = %v", err)
	}
	if errors.Is(err, spaces.ErrForbidden) {
		t.Fatalf("cross-Space error leaked authorization: %v", err)
	}
	if !h.membershipExists(t, spaceID, "owner") {
		t.Fatal("test setup lost owner membership")
	}
}

func TestChangeRoleRevokesTargetSessionsInSameTransaction(t *testing.T) {
	h := newSpacesHarness(t)
	spaceID := h.createSpace(t, "owner")
	if err := h.service.AddMember(
		h.ctx, h.principal("owner"), spaceID, "member", spaces.Reader,
	); err != nil {
		t.Fatal(err)
	}
	h.insertSession(t, "member", "member-session")

	if err := h.service.ChangeRole(
		h.ctx, h.principal("owner"), spaceID, "member", spaces.Editor,
	); err != nil {
		t.Fatal(err)
	}
	if role := h.membershipRole(t, spaceID, "member"); role != spaces.Editor {
		t.Fatalf("member role = %q, want Editor", role)
	}
	if !h.sessionRevoked(t, "member-session") {
		t.Fatal("target session remained active")
	}
	if got := h.revoker.callsFor("member"); got != 1 {
		t.Fatalf("revoke calls = %d, want 1", got)
	}
}

func TestChangeRoleRollsBackWhenSessionRevocationFails(t *testing.T) {
	h := newSpacesHarness(t)
	spaceID := h.createSpace(t, "owner")
	if err := h.service.AddMember(
		h.ctx, h.principal("owner"), spaceID, "member", spaces.Reader,
	); err != nil {
		t.Fatal(err)
	}
	h.insertSession(t, "member", "member-session")
	h.revoker.failAfterUpdate = errors.New("revocation unavailable")

	err := h.service.ChangeRole(
		h.ctx, h.principal("owner"), spaceID, "member", spaces.Editor,
	)
	if !errors.Is(err, h.revoker.failAfterUpdate) {
		t.Fatalf("ChangeRole error = %v", err)
	}
	if role := h.membershipRole(t, spaceID, "member"); role != spaces.Reader {
		t.Fatalf("rolled-back role = %q, want Reader", role)
	}
	if h.sessionRevoked(t, "member-session") {
		t.Fatal("session revocation was not rolled back")
	}
}

func TestRemoveMemberRevokesTargetSessionsAtomically(t *testing.T) {
	h := newSpacesHarness(t)
	spaceID := h.createSpace(t, "owner")
	if err := h.service.AddMember(
		h.ctx, h.principal("owner"), spaceID, "member", spaces.Reader,
	); err != nil {
		t.Fatal(err)
	}
	h.insertSession(t, "member", "member-session")

	if err := h.service.RemoveMember(
		h.ctx, h.principal("owner"), spaceID, "member",
	); err != nil {
		t.Fatal(err)
	}
	if h.membershipExists(t, spaceID, "member") {
		t.Fatal("removed membership still exists")
	}
	if !h.sessionRevoked(t, "member-session") {
		t.Fatal("removed member session remained active")
	}
}

func TestRemoveMemberRollsBackWhenSessionRevocationFails(t *testing.T) {
	h := newSpacesHarness(t)
	spaceID := h.createSpace(t, "owner")
	if err := h.service.AddMember(
		h.ctx, h.principal("owner"), spaceID, "member", spaces.Reader,
	); err != nil {
		t.Fatal(err)
	}
	h.insertSession(t, "member", "member-session")
	h.revoker.failAfterUpdate = errors.New("revocation unavailable")

	err := h.service.RemoveMember(
		h.ctx, h.principal("owner"), spaceID, "member",
	)
	if !errors.Is(err, h.revoker.failAfterUpdate) {
		t.Fatalf("RemoveMember error = %v", err)
	}
	if !h.membershipExists(t, spaceID, "member") {
		t.Fatal("membership removal was not rolled back")
	}
	if h.sessionRevoked(t, "member-session") {
		t.Fatal("session revocation was not rolled back")
	}
}

func TestLastSpaceOwnerCannotBeRemovedOrDowngraded(t *testing.T) {
	h := newSpacesHarness(t)
	spaceID := h.createSpace(t, "owner")
	h.insertSession(t, "owner", "owner-session")

	if err := h.service.ChangeRole(
		h.ctx, h.principal("owner"), spaceID, "owner", spaces.Editor,
	); !errors.Is(err, spaces.ErrLastOwner) {
		t.Fatalf("last-owner downgrade error = %v", err)
	}
	if role := h.membershipRole(t, spaceID, "owner"); role != spaces.Owner {
		t.Fatalf("owner role after downgrade = %q", role)
	}
	if err := h.service.RemoveMember(
		h.ctx, h.principal("owner"), spaceID, "owner",
	); !errors.Is(err, spaces.ErrLastOwner) {
		t.Fatalf("last-owner removal error = %v", err)
	}
	if !h.membershipExists(t, spaceID, "owner") {
		t.Fatal("last owner was removed")
	}
	if h.sessionRevoked(t, "owner-session") {
		t.Fatal("rejected last-owner mutation revoked the actor session")
	}
	if got := h.revoker.callsFor("owner"); got != 0 {
		t.Fatalf("revoke calls = %d, want 0", got)
	}
}

func TestOwnerCanTransferOwnershipBeforeLeaving(t *testing.T) {
	h := newSpacesHarness(t)
	spaceID := h.createSpace(t, "owner")
	if err := h.service.AddMember(
		h.ctx, h.principal("owner"), spaceID, "member", spaces.Editor,
	); err != nil {
		t.Fatal(err)
	}
	if err := h.service.ChangeRole(
		h.ctx, h.principal("owner"), spaceID, "member", spaces.Owner,
	); err != nil {
		t.Fatal(err)
	}
	if err := h.service.RemoveMember(
		h.ctx, h.principal("member"), spaceID, "owner",
	); err != nil {
		t.Fatal(err)
	}
	if h.membershipExists(t, spaceID, "owner") {
		t.Fatal("former owner membership still exists")
	}
	if role := h.membershipRole(t, spaceID, "member"); role != spaces.Owner {
		t.Fatalf("new owner role = %q", role)
	}
}

func TestMembershipInputValidationAndConflicts(t *testing.T) {
	h := newSpacesHarness(t)
	spaceID := h.createSpace(t, "owner")

	if err := h.service.AddMember(
		h.ctx, h.principal("owner"), spaceID, "member", spaces.Role("root"),
	); !errors.Is(err, spaces.ErrInvalidRole) {
		t.Fatalf("invalid role error = %v", err)
	}
	if err := h.service.AddMember(
		h.ctx, h.principal("owner"), spaceID, "missing-user", spaces.Reader,
	); !errors.Is(err, spaces.ErrUserNotFound) {
		t.Fatalf("missing user error = %v", err)
	}
	if err := h.service.AddMember(
		h.ctx, h.principal("owner"), spaceID, "member", spaces.Reader,
	); err != nil {
		t.Fatal(err)
	}
	if err := h.service.AddMember(
		h.ctx, h.principal("owner"), spaceID, "member", spaces.Editor,
	); !errors.Is(err, spaces.ErrMembershipExists) {
		t.Fatalf("duplicate membership error = %v", err)
	}
	if err := h.service.ChangeRole(
		h.ctx, h.principal("owner"), spaceID, "editor", spaces.Reader,
	); !errors.Is(err, spaces.ErrMembershipNotFound) {
		t.Fatalf("missing membership error = %v", err)
	}
}

func TestSystemOwnerCanManageAnySpaceAndListAllSpaces(t *testing.T) {
	h := newSpacesHarness(t)
	spaceID := h.createSpace(t, "member")
	h.mustExec(`UPDATE users SET system_role = ? WHERE id = ?`, identity.SystemRoleOwner, "owner")

	if err := h.service.AddMember(
		h.ctx, h.principal("owner"), spaceID, "editor", spaces.Reader,
	); err != nil {
		t.Fatal(err)
	}
	rows, err := h.service.ListForUser(h.ctx, h.principal("owner"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != spaceID {
		t.Fatalf("System Owner Spaces = %+v", rows)
	}
}

func TestSystemOwnerMutationsConcealMissingOrDeletedSpace(t *testing.T) {
	tests := []struct {
		name     string
		spaceID  func(*testing.T, *spacesHarness) string
		mutation func(*spacesHarness, string) error
	}{
		{
			name: "add member to missing Space",
			spaceID: func(*testing.T, *spacesHarness) string {
				return "missing-space"
			},
			mutation: func(h *spacesHarness, spaceID string) error {
				return h.service.AddMember(
					h.ctx, h.principal("owner"), spaceID, "editor", spaces.Reader,
				)
			},
		},
		{
			name: "change role in missing Space",
			spaceID: func(*testing.T, *spacesHarness) string {
				return "missing-space"
			},
			mutation: func(h *spacesHarness, spaceID string) error {
				return h.service.ChangeRole(
					h.ctx, h.principal("owner"), spaceID, "member", spaces.Editor,
				)
			},
		},
		{
			name: "remove member from missing Space",
			spaceID: func(*testing.T, *spacesHarness) string {
				return "missing-space"
			},
			mutation: func(h *spacesHarness, spaceID string) error {
				return h.service.RemoveMember(
					h.ctx, h.principal("owner"), spaceID, "member",
				)
			},
		},
		{
			name: "add member to deleted Space",
			spaceID: func(t *testing.T, h *spacesHarness) string {
				return h.softDeletedSpace(t)
			},
			mutation: func(h *spacesHarness, spaceID string) error {
				return h.service.AddMember(
					h.ctx, h.principal("owner"), spaceID, "editor", spaces.Reader,
				)
			},
		},
		{
			name: "change role in deleted Space",
			spaceID: func(t *testing.T, h *spacesHarness) string {
				return h.softDeletedSpace(t)
			},
			mutation: func(h *spacesHarness, spaceID string) error {
				return h.service.ChangeRole(
					h.ctx, h.principal("owner"), spaceID, "member", spaces.Editor,
				)
			},
		},
		{
			name: "remove member from deleted Space",
			spaceID: func(t *testing.T, h *spacesHarness) string {
				return h.softDeletedSpace(t)
			},
			mutation: func(h *spacesHarness, spaceID string) error {
				return h.service.RemoveMember(
					h.ctx, h.principal("owner"), spaceID, "member",
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newSpacesHarness(t)
			h.mustExec(
				`UPDATE users SET system_role = ? WHERE id = ?`,
				identity.SystemRoleOwner, "owner",
			)
			spaceID := test.spaceID(t, h)

			if err := test.mutation(h, spaceID); err != spaces.ErrNotFound {
				t.Fatalf("mutation error = %v, want stable ErrNotFound", err)
			}
			if len(h.revoker.calls) != 0 {
				t.Fatalf("session revocations = %+v", h.revoker.calls)
			}
		})
	}
}

func TestSpaceOwnerCannotMutateSoftDeletedSpace(t *testing.T) {
	h := newSpacesHarness(t)
	spaceID := h.createSpace(t, "owner")
	h.mustExec(`UPDATE spaces SET deleted_at = ? WHERE id = ?`, h.nowString(), spaceID)

	err := h.service.AddMember(
		h.ctx, h.principal("owner"), spaceID, "member", spaces.Reader,
	)
	if err != spaces.ErrNotFound {
		t.Fatalf("mutation error = %v, want stable ErrNotFound", err)
	}
	if h.membershipExists(t, spaceID, "member") {
		t.Fatal("member was added to deleted Space")
	}
}

type spacesHarness struct {
	ctx     context.Context
	db      *storage.DB
	service *spaces.Service
	revoker *recordingRevoker
	now     time.Time
}

func newSpacesHarness(t *testing.T) *spacesHarness {
	t.Helper()
	ctx := context.Background()
	db, err := storage.Open(filepath.Join(t.TempDir(), "opswarden.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	revoker := &recordingRevoker{}
	service, err := spaces.NewService(db, revoker)
	if err != nil {
		t.Fatal(err)
	}
	h := &spacesHarness{
		ctx: ctx, db: db, service: service, revoker: revoker,
		now: time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC),
	}
	for _, userID := range []string{"owner", "editor", "member"} {
		h.mustExec(`
			INSERT INTO users
				(id, email, normalized_email, password_hash, system_role, created_at, updated_at)
			VALUES (?, ?, ?, X'01', ?, ?, ?)
		`, userID, userID+"@example.com", userID+"@example.com",
			identity.SystemRoleMember, h.nowString(), h.nowString())
	}
	return h
}

func (h *spacesHarness) principal(userID string) identity.SessionPrincipal {
	return identity.SessionPrincipal{
		UserID: userID, SessionID: "authenticated-session-" + userID,
		IssuedAt: h.now,
	}
}

func (h *spacesHarness) createSpace(t *testing.T, userID string) string {
	t.Helper()
	created, err := h.service.Create(
		h.ctx, h.principal(userID), spaces.CreateInput{Name: "Space for " + userID},
	)
	if err != nil {
		t.Fatal(err)
	}
	return created.ID
}

func (h *spacesHarness) softDeletedSpace(t *testing.T) string {
	t.Helper()
	spaceID := h.createSpace(t, "member")
	h.mustExec(`UPDATE spaces SET deleted_at = ? WHERE id = ?`, h.nowString(), spaceID)
	return spaceID
}

func (h *spacesHarness) membershipRole(
	t *testing.T,
	spaceID, userID string,
) spaces.Role {
	t.Helper()
	var role spaces.Role
	if err := h.db.Reader.QueryRowContext(h.ctx, `
		SELECT role FROM space_memberships WHERE space_id = ? AND user_id = ?
	`, spaceID, userID).Scan(&role); err != nil {
		t.Fatal(err)
	}
	return role
}

func (h *spacesHarness) membershipExists(t *testing.T, spaceID, userID string) bool {
	t.Helper()
	var count int
	if err := h.db.Reader.QueryRowContext(h.ctx, `
		SELECT count(*) FROM space_memberships WHERE space_id = ? AND user_id = ?
	`, spaceID, userID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count == 1
}

func (h *spacesHarness) insertSession(t *testing.T, userID, sessionID string) {
	t.Helper()
	h.mustExec(`
		INSERT INTO sessions
			(id, user_id, token_hash, created_at, expires_at, idle_expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, sessionID, userID, []byte("hash-"+sessionID), h.nowString(),
		h.now.Add(time.Hour).Format(time.RFC3339Nano),
		h.now.Add(time.Hour).Format(time.RFC3339Nano))
}

func (h *spacesHarness) sessionRevoked(t *testing.T, sessionID string) bool {
	t.Helper()
	var revokedAt sql.NullString
	if err := h.db.Reader.QueryRowContext(h.ctx,
		`SELECT revoked_at FROM sessions WHERE id = ?`, sessionID,
	).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	return revokedAt.Valid
}

func (h *spacesHarness) mustExec(statement string, args ...any) {
	if _, err := h.db.Writer.ExecContext(h.ctx, statement, args...); err != nil {
		panic(err)
	}
}

func (h *spacesHarness) nowString() string {
	return h.now.Format(time.RFC3339Nano)
}

type recordingRevoker struct {
	calls           []string
	failAfterUpdate error
}

func (r *recordingRevoker) RevokeUserSessionsTx(
	ctx context.Context,
	tx *sql.Tx,
	userID string,
) error {
	r.calls = append(r.calls, userID)
	if _, err := tx.ExecContext(ctx, `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, ?)
		WHERE user_id = ?
	`, time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		userID); err != nil {
		return err
	}
	return r.failAfterUpdate
}

func (r *recordingRevoker) callsFor(userID string) int {
	var count int
	for _, calledUserID := range r.calls {
		if calledUserID == userID {
			count++
		}
	}
	return count
}
