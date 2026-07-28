package authorization_test

import (
	"errors"
	"testing"

	"opswarden/internal/authorization"
	"opswarden/internal/identity"
	"opswarden/internal/spaces"
)

func TestPolicyErrorsRemainDistinct(t *testing.T) {
	if errors.Is(authorization.ErrNotFound, authorization.ErrDenied) {
		t.Fatal("concealed not-found must remain distinct from explicit forbidden")
	}
}

func TestHumanRolePermissionMatrixIsExhaustive(t *testing.T) {
	const spaceID = "space-production"
	spaceActions := map[authorization.Action]map[spaces.Role]bool{
		authorization.ListCredential:    {spaces.Owner: true, spaces.Editor: true, spaces.Reader: true},
		authorization.ReadCredential:    {spaces.Owner: true, spaces.Editor: true, spaces.Reader: true},
		authorization.CreateCredential:  {spaces.Owner: true, spaces.Editor: true},
		authorization.UpdateCredential:  {spaces.Owner: true, spaces.Editor: true},
		authorization.DeleteCredential:  {spaces.Owner: true, spaces.Editor: true},
		authorization.RestoreCredential: {spaces.Owner: true},
		authorization.PurgeCredential:   {},
		authorization.GenerateTOTP:      {spaces.Owner: true, spaces.Editor: true, spaces.Reader: true},
		authorization.ListAsset:         {spaces.Owner: true, spaces.Editor: true, spaces.Reader: true},
		authorization.ReadAsset:         {spaces.Owner: true, spaces.Editor: true, spaces.Reader: true},
		authorization.CreateAsset:       {spaces.Owner: true, spaces.Editor: true},
		authorization.UpdateAsset:       {spaces.Owner: true, spaces.Editor: true},
		authorization.DeleteAsset:       {spaces.Owner: true, spaces.Editor: true},
		authorization.LinkCredential:    {spaces.Owner: true, spaces.Editor: true},
		authorization.ListMembers:       {spaces.Owner: true, spaces.Editor: true, spaces.Reader: true},
		authorization.ManageMembers:     {spaces.Owner: true},
		authorization.AddMember:         {spaces.Owner: true},
		authorization.ChangeMemberRole:  {spaces.Owner: true},
		authorization.RemoveMember:      {spaces.Owner: true},
		authorization.ManageAgentGrant:  {spaces.Owner: true},
		authorization.ListAuditEvents:   {spaces.Owner: true},
		authorization.PurgeAuditEvents:  {},
	}
	globalActions := map[authorization.Action]struct{}{
		authorization.CreateSpace:      {},
		authorization.ListSpaces:       {},
		authorization.ListAgents:       {},
		authorization.ReadAgent:        {},
		authorization.CreateAgent:      {},
		authorization.UpdateAgent:      {},
		authorization.DeleteAgent:      {},
		authorization.IssueAgentToken:  {},
		authorization.RevokeAgentToken: {},
		authorization.ListBackups:      {},
		authorization.CreateBackup:     {},
		authorization.RestoreBackup:    {},
		authorization.ReadSettings:     {},
		authorization.UpdateSettings:   {},
		authorization.ManageUsers:      {},
		authorization.ReadHealth:       {},
	}
	if got, want := len(spaceActions)+len(globalActions), len(authorization.AllActions()); got != want {
		t.Fatalf("classified actions = %d, AllActions = %d", got, want)
	}

	for action, allowedRoles := range spaceActions {
		for _, role := range []spaces.Role{spaces.Owner, spaces.Editor, spaces.Reader} {
			t.Run(string(role)+"/"+string(action), func(t *testing.T) {
				principal := authorization.HumanPrincipal{
					Session: identity.SessionPrincipal{
						UserID: "user-1", SessionID: "session-1",
					},
					SystemRole: identity.SystemRoleMember,
					SpaceRoles: map[string]authorization.Role{spaceID: role},
				}
				got := authorization.DecisionForHuman(
					principal,
					authorization.Resource{SpaceID: spaceID, ResourceID: "resource-1"},
					action,
				)
				if got.Allowed != allowedRoles[role] {
					t.Fatalf("decision = %+v, want allowed=%v", got, allowedRoles[role])
				}
				if !got.Allowed && got.Conceal {
					t.Fatalf("same-Space role denial unexpectedly concealed: %+v", got)
				}
			})
		}
	}
}

func TestHumanGlobalAndSystemRolePermissions(t *testing.T) {
	session := identity.SessionPrincipal{UserID: "user-1", SessionID: "session-1"}

	for _, action := range []authorization.Action{
		authorization.CreateSpace,
		authorization.ListSpaces,
	} {
		decision := authorization.DecisionForHuman(
			authorization.HumanPrincipal{Session: session, SystemRole: identity.SystemRoleMember},
			authorization.Resource{},
			action,
		)
		if !decision.Allowed {
			t.Fatalf("authenticated member %s decision = %+v", action, decision)
		}
	}

	adminAllowed := map[authorization.Action]bool{
		authorization.RestoreCredential: true,
		authorization.ListAuditEvents:   true,
		authorization.PurgeAuditEvents:  true,
		authorization.ListBackups:       true,
		authorization.CreateBackup:      true,
		authorization.RestoreBackup:     true,
		authorization.ReadSettings:      true,
		authorization.UpdateSettings:    true,
		authorization.ManageUsers:       true,
		authorization.ReadHealth:        true,
		authorization.ListAgents:        true,
		authorization.ReadAgent:         true,
		authorization.CreateAgent:       true,
		authorization.UpdateAgent:       true,
		authorization.DeleteAgent:       true,
		authorization.IssueAgentToken:   true,
		authorization.RevokeAgentToken:  true,
		authorization.ManageAgentGrant:  true,
	}
	for _, action := range authorization.AllActions() {
		resource := authorization.Resource{}
		if action == authorization.RestoreCredential ||
			action == authorization.ListAuditEvents ||
			action == authorization.ManageAgentGrant {
			resource.SpaceID = "space-1"
		}
		decision := authorization.DecisionForHuman(
			authorization.HumanPrincipal{
				Session: session, SystemRole: identity.SystemRoleAdmin,
			},
			resource,
			action,
		)
		want := adminAllowed[action] ||
			action == authorization.CreateSpace ||
			action == authorization.ListSpaces
		if decision.Allowed != want {
			t.Fatalf("System Admin %s decision = %+v, want allowed=%v", action, decision, want)
		}

		ownerDecision := authorization.DecisionForHuman(
			authorization.HumanPrincipal{
				Session: session, SystemRole: identity.SystemRoleOwner,
			},
			resource,
			action,
		)
		if !ownerDecision.Allowed {
			t.Fatalf("System Owner %s decision = %+v", action, ownerDecision)
		}
	}
}

func TestSpaceOwnerCanManageOnlyOwnSpaceGrantNotAgentLifecycle(t *testing.T) {
	principal := authorization.HumanPrincipal{
		Session: identity.SessionPrincipal{
			UserID: "space-owner", SessionID: "session-1",
		},
		SystemRole: identity.SystemRoleMember,
		SpaceRoles: map[string]authorization.Role{
			"space-a": spaces.Owner,
		},
	}
	ownGrant := authorization.DecisionForHuman(
		principal,
		authorization.Resource{SpaceID: "space-a", ResourceID: "agent-1"},
		authorization.ManageAgentGrant,
	)
	if !ownGrant.Allowed {
		t.Fatalf("own-Space grant decision = %+v", ownGrant)
	}
	otherGrant := authorization.DecisionForHuman(
		principal,
		authorization.Resource{SpaceID: "space-b", ResourceID: "agent-1"},
		authorization.ManageAgentGrant,
	)
	if otherGrant.Allowed || !otherGrant.Conceal {
		t.Fatalf("other-Space grant decision = %+v", otherGrant)
	}

	for _, action := range []authorization.Action{
		authorization.ListAgents,
		authorization.ReadAgent,
		authorization.CreateAgent,
		authorization.UpdateAgent,
		authorization.DeleteAgent,
		authorization.IssueAgentToken,
		authorization.RevokeAgentToken,
	} {
		decision := authorization.DecisionForHuman(
			principal,
			authorization.Resource{ResourceID: "agent-1"},
			action,
		)
		if decision.Allowed || decision.Conceal {
			t.Fatalf("%s decision = %+v", action, decision)
		}
	}
}

func TestManageAgentGrantRequiresResourceSpace(t *testing.T) {
	for _, systemRole := range []string{
		identity.SystemRoleOwner,
		identity.SystemRoleAdmin,
	} {
		decision := authorization.DecisionForHuman(
			authorization.HumanPrincipal{
				Session: identity.SessionPrincipal{
					UserID: "system-user", SessionID: "session-1",
				},
				SystemRole: systemRole,
			},
			authorization.Resource{ResourceID: "agent-1"},
			authorization.ManageAgentGrant,
		)
		if decision.Allowed || !decision.Conceal {
			t.Fatalf("%s decision = %+v", systemRole, decision)
		}
	}
}

func TestEditorCannotManageAgentGrantInOwnSpace(t *testing.T) {
	decision := authorization.DecisionForHuman(
		authorization.HumanPrincipal{
			Session: identity.SessionPrincipal{
				UserID: "editor", SessionID: "session-1",
			},
			SpaceRoles: map[string]authorization.Role{
				"space-a": spaces.Editor,
			},
		},
		authorization.Resource{SpaceID: "space-a", ResourceID: "agent-1"},
		authorization.ManageAgentGrant,
	)
	if decision.Allowed || decision.Conceal {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestHumanCrossSpaceAndUnknownResourceAreConcealed(t *testing.T) {
	principal := authorization.HumanPrincipal{
		Session: identity.SessionPrincipal{UserID: "reader", SessionID: "session"},
		SpaceRoles: map[string]authorization.Role{
			"space-a": spaces.Reader,
		},
	}
	for _, resource := range []authorization.Resource{
		{SpaceID: "space-b", ResourceID: "credential-from-space-b"},
		{SpaceID: "", ResourceID: "unresolved-credential"},
	} {
		decision := authorization.DecisionForHuman(
			principal, resource, authorization.ReadCredential,
		)
		if decision.Allowed || !decision.Conceal ||
			decision.Reason != authorization.CodeConcealedNotFound {
			t.Fatalf("decision = %+v", decision)
		}
		if err := decision.Err(); err != authorization.ErrNotFound {
			t.Fatalf("decision error = %v, want ErrNotFound", err)
		}
	}
}

func TestInvalidHumanPrincipalIsUnauthenticated(t *testing.T) {
	decision := authorization.DecisionForHuman(
		authorization.HumanPrincipal{},
		authorization.Resource{SpaceID: "space-1"},
		authorization.ListCredential,
	)
	if decision.Allowed || decision.Conceal ||
		decision.Reason != authorization.CodeUnauthenticated {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestAgentScopeMatrixIsExhaustive(t *testing.T) {
	scopeActions := map[authorization.Scope][]authorization.Action{
		authorization.ScopeCredentialList: {
			authorization.ListCredential,
		},
		authorization.ScopeCredentialRead: {
			authorization.ReadCredential,
			authorization.GenerateTOTP,
		},
		authorization.ScopeCredentialCreate: {
			authorization.CreateCredential,
		},
		authorization.ScopeCredentialUpdate: {
			authorization.UpdateCredential,
		},
		authorization.ScopeCredentialDelete: {
			authorization.DeleteCredential,
		},
		authorization.ScopeAssetList: {
			authorization.ListAsset,
		},
		authorization.ScopeAssetRead: {
			authorization.ReadAsset,
		},
	}
	if got, want := len(scopeActions), len(authorization.AllScopes()); got != want {
		t.Fatalf("classified scopes = %d, AllScopes = %d", got, want)
	}
	for scope, actions := range scopeActions {
		for _, action := range actions {
			t.Run(string(scope)+"/"+string(action), func(t *testing.T) {
				decision := authorization.DecisionForAgent(
					authorization.AgentPrincipal{
						AgentID: "agent-1",
						Grants: []authorization.Grant{{
							SpaceID: "space-1",
							Scopes:  map[authorization.Scope]struct{}{scope: {}},
						}},
					},
					authorization.Resource{
						SpaceID: "space-1", ResourceID: "resource-1",
					},
					action,
				)
				if !decision.Allowed {
					t.Fatalf("decision = %+v", decision)
				}
			})
		}
	}
}

func TestAgentSpaceAndLabelsCanOnlyNarrowAccess(t *testing.T) {
	principal := authorization.AgentPrincipal{
		AgentID: "agent-1",
		Grants: []authorization.Grant{{
			SpaceID: "space-dev",
			Scopes: map[authorization.Scope]struct{}{
				authorization.ScopeCredentialRead: {},
			},
			Labels: map[string]string{
				"environment": "dev",
				"team":        "platform",
			},
		}},
	}
	tests := []struct {
		name     string
		resource authorization.Resource
		action   authorization.Action
		allowed  bool
	}{
		{
			name: "all labels match",
			resource: authorization.Resource{
				SpaceID: "space-dev", ResourceID: "credential-1",
				Labels: map[string]string{
					"environment": "dev", "team": "platform", "extra": "allowed",
				},
			},
			action: authorization.ReadCredential, allowed: true,
		},
		{
			name: "label mismatch cannot expand",
			resource: authorization.Resource{
				SpaceID: "space-dev", ResourceID: "credential-2",
				Labels: map[string]string{"environment": "prod", "team": "platform"},
			},
			action: authorization.ReadCredential,
		},
		{
			name: "missing label cannot expand",
			resource: authorization.Resource{
				SpaceID: "space-dev", ResourceID: "credential-3",
				Labels: map[string]string{"environment": "dev"},
			},
			action: authorization.ReadCredential,
		},
		{
			name: "cross Space cannot expand",
			resource: authorization.Resource{
				SpaceID: "space-prod", ResourceID: "credential-4",
				Labels: map[string]string{"environment": "dev", "team": "platform"},
			},
			action: authorization.ReadCredential,
		},
		{
			name: "scope cannot expand",
			resource: authorization.Resource{
				SpaceID: "space-dev", ResourceID: "credential-5",
				Labels: map[string]string{"environment": "dev", "team": "platform"},
			},
			action: authorization.UpdateCredential,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := authorization.DecisionForAgent(principal, test.resource, test.action)
			if decision.Allowed != test.allowed {
				t.Fatalf("decision = %+v, want allowed=%v", decision, test.allowed)
			}
			if !test.allowed && (!decision.Conceal ||
				decision.Reason != authorization.CodeConcealedNotFound) {
				t.Fatalf("denial did not conceal resource: %+v", decision)
			}
		})
	}
}

func TestAgentRequiredEmptyLabelValueRequiresExplicitKeyPresence(t *testing.T) {
	principal := authorization.AgentPrincipal{
		AgentID: "agent-1",
		Grants: []authorization.Grant{{
			SpaceID: "space-1",
			Scopes: map[authorization.Scope]struct{}{
				authorization.ScopeCredentialRead: {},
			},
			Labels: map[string]string{"environment": ""},
		}},
	}
	tests := []struct {
		name    string
		labels  map[string]string
		allowed bool
	}{
		{name: "missing key", labels: map[string]string{}},
		{
			name: "explicit empty value",
			labels: map[string]string{
				"environment": "",
			},
			allowed: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := authorization.DecisionForAgent(
				principal,
				authorization.Resource{
					SpaceID: "space-1", ResourceID: "credential-1",
					Labels: test.labels,
				},
				authorization.ReadCredential,
			)
			if decision.Allowed != test.allowed {
				t.Fatalf("decision = %+v, want allowed=%v", decision, test.allowed)
			}
		})
	}
}

func TestAgentGrantRejectsEmptyLabelKey(t *testing.T) {
	grant := authorization.Grant{
		SpaceID: "space-1",
		Scopes: map[authorization.Scope]struct{}{
			authorization.ScopeCredentialRead: {},
		},
		Labels: map[string]string{"": "dev"},
	}
	if err := authorization.ValidateGrant(grant); !errors.Is(
		err, authorization.ErrInvalidGrant,
	) {
		t.Fatalf("ValidateGrant error = %v", err)
	}

	decision := authorization.DecisionForAgent(
		authorization.AgentPrincipal{
			AgentID: "agent-1", Grants: []authorization.Grant{grant},
		},
		authorization.Resource{
			SpaceID: "space-1", ResourceID: "credential-1",
			Labels: map[string]string{"": "dev"},
		},
		authorization.ReadCredential,
	)
	if decision.Allowed || !decision.Conceal {
		t.Fatalf("invalid grant decision = %+v", decision)
	}
}

func TestAgentCannotCombineScopeAndLabelsAcrossGrants(t *testing.T) {
	principal := authorization.AgentPrincipal{
		AgentID: "agent-1",
		Grants: []authorization.Grant{
			{
				SpaceID: "space-1",
				Scopes: map[authorization.Scope]struct{}{
					authorization.ScopeCredentialRead: {},
				},
				Labels: map[string]string{"environment": "dev"},
			},
			{
				SpaceID: "space-1",
				Scopes:  map[authorization.Scope]struct{}{},
				Labels:  map[string]string{"environment": "prod"},
			},
		},
	}
	decision := authorization.DecisionForAgent(
		principal,
		authorization.Resource{
			SpaceID: "space-1", ResourceID: "credential-prod",
			Labels: map[string]string{"environment": "prod"},
		},
		authorization.ReadCredential,
	)
	if decision.Allowed || !decision.Conceal {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestAgentNeverReceivesHumanOrAssetMutationPermissions(t *testing.T) {
	principal := authorization.AgentPrincipal{
		AgentID: "agent-1",
		Grants: []authorization.Grant{{
			SpaceID: "space-1",
			Scopes: map[authorization.Scope]struct{}{
				authorization.ScopeCredentialList:   {},
				authorization.ScopeCredentialRead:   {},
				authorization.ScopeCredentialCreate: {},
				authorization.ScopeCredentialUpdate: {},
				authorization.ScopeCredentialDelete: {},
				authorization.ScopeAssetList:        {},
				authorization.ScopeAssetRead:        {},
			},
		}},
	}
	for _, action := range []authorization.Action{
		authorization.ManageMembers,
		authorization.PurgeCredential,
		authorization.RestoreCredential,
		authorization.CreateAsset,
		authorization.UpdateAsset,
		authorization.DeleteAsset,
		authorization.CreateAgent,
		authorization.ListAuditEvents,
		authorization.CreateBackup,
		authorization.UpdateSettings,
	} {
		decision := authorization.DecisionForAgent(
			principal,
			authorization.Resource{SpaceID: "space-1", ResourceID: "resource-1"},
			action,
		)
		if decision.Allowed || !decision.Conceal {
			t.Fatalf("%s decision = %+v", action, decision)
		}
	}
}

func TestUnknownActionIsDenied(t *testing.T) {
	resource := authorization.Resource{SpaceID: "space-1", ResourceID: "resource-1"}
	human := authorization.DecisionForHuman(
		authorization.HumanPrincipal{
			Session:    identity.SessionPrincipal{UserID: "owner", SessionID: "session"},
			SystemRole: identity.SystemRoleOwner,
		},
		resource,
		authorization.Action("unknown"),
	)
	if human.Allowed || human.Reason != authorization.CodeInvalidAction {
		t.Fatalf("human decision = %+v", human)
	}
	agent := authorization.DecisionForAgent(
		authorization.AgentPrincipal{AgentID: "agent"},
		resource,
		authorization.Action("unknown"),
	)
	if agent.Allowed || !agent.Conceal ||
		agent.Reason != authorization.CodeConcealedNotFound {
		t.Fatalf("agent decision = %+v", agent)
	}
}
