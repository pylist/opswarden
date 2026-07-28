package authorization

import (
	"errors"

	"opswarden/internal/identity"
)

type Action string

const (
	CreateSpace Action = "space.create"
	ListSpaces  Action = "space.list"

	ListCredential    Action = "credential.list"
	ReadCredential    Action = "credential.read"
	CreateCredential  Action = "credential.create"
	UpdateCredential  Action = "credential.update"
	DeleteCredential  Action = "credential.delete"
	RestoreCredential Action = "credential.restore"
	PurgeCredential   Action = "credential.purge"
	GenerateTOTP      Action = "credential.totp.generate"

	ListAsset      Action = "asset.list"
	ReadAsset      Action = "asset.read"
	CreateAsset    Action = "asset.create"
	UpdateAsset    Action = "asset.update"
	DeleteAsset    Action = "asset.delete"
	LinkCredential Action = "asset.credential.link"

	ListMembers      Action = "membership.list"
	ManageMembers    Action = "membership.manage"
	AddMember        Action = "membership.add"
	ChangeMemberRole Action = "membership.role.change"
	RemoveMember     Action = "membership.remove"

	ListAgents        Action = "agent.list"
	ReadAgent         Action = "agent.read"
	CreateAgent       Action = "agent.create"
	UpdateAgent       Action = "agent.update"
	DeleteAgent       Action = "agent.delete"
	IssueAgentToken   Action = "agent.token.issue"
	RevokeAgentToken  Action = "agent.token.revoke"
	ManageAgentGrants Action = "agent.grant.manage"

	ListAuditEvents  Action = "audit.list"
	PurgeAuditEvents Action = "audit.purge"

	ListBackups   Action = "backup.list"
	CreateBackup  Action = "backup.create"
	RestoreBackup Action = "backup.restore"

	ReadSettings   Action = "settings.read"
	UpdateSettings Action = "settings.update"
	ManageUsers    Action = "settings.users.manage"
	ReadHealth     Action = "settings.health.read"
)

var allActions = []Action{
	CreateSpace,
	ListSpaces,
	ListCredential,
	ReadCredential,
	CreateCredential,
	UpdateCredential,
	DeleteCredential,
	RestoreCredential,
	PurgeCredential,
	GenerateTOTP,
	ListAsset,
	ReadAsset,
	CreateAsset,
	UpdateAsset,
	DeleteAsset,
	LinkCredential,
	ListMembers,
	ManageMembers,
	AddMember,
	ChangeMemberRole,
	RemoveMember,
	ListAgents,
	ReadAgent,
	CreateAgent,
	UpdateAgent,
	DeleteAgent,
	IssueAgentToken,
	RevokeAgentToken,
	ManageAgentGrants,
	ListAuditEvents,
	PurgeAuditEvents,
	ListBackups,
	CreateBackup,
	RestoreBackup,
	ReadSettings,
	UpdateSettings,
	ManageUsers,
	ReadHealth,
}

type Role string

const (
	RoleOwner  Role = "owner"
	RoleEditor Role = "editor"
	RoleReader Role = "reader"
)

func (r Role) Valid() bool {
	switch r {
	case RoleOwner, RoleEditor, RoleReader:
		return true
	default:
		return false
	}
}

type Scope string

const (
	ScopeCredentialList   Scope = "credential:list"
	ScopeCredentialRead   Scope = "credential:read"
	ScopeCredentialCreate Scope = "credential:create"
	ScopeCredentialUpdate Scope = "credential:update"
	ScopeCredentialDelete Scope = "credential:delete"
	ScopeAssetList        Scope = "asset:list"
	ScopeAssetRead        Scope = "asset:read"
)

var allScopes = []Scope{
	ScopeCredentialList,
	ScopeCredentialRead,
	ScopeCredentialCreate,
	ScopeCredentialUpdate,
	ScopeCredentialDelete,
	ScopeAssetList,
	ScopeAssetRead,
}

type Resource struct {
	SpaceID    string
	ResourceID string
	Labels     map[string]string
}

type Code string

const (
	CodeAllowed           Code = "allowed"
	CodeUnauthenticated   Code = "unauthenticated"
	CodeForbidden         Code = "forbidden"
	CodeConcealedNotFound Code = "concealed_not_found"
	CodeInvalidAction     Code = "invalid_action"
)

var (
	ErrDenied          = errors.New("authorization denied")
	ErrNotFound        = errors.New("resource not found")
	ErrUnauthenticated = errors.New("principal is not authenticated")
)

type Decision struct {
	Allowed bool
	Conceal bool
	Reason  Code
}

func (d Decision) Err() error {
	if d.Allowed {
		return nil
	}
	if d.Reason == CodeUnauthenticated {
		return ErrUnauthenticated
	}
	if d.Conceal {
		return ErrNotFound
	}
	return ErrDenied
}

type HumanPrincipal struct {
	Session    identity.SessionPrincipal
	SystemRole string
	SpaceRoles map[string]Role
}

type AgentPrincipal struct {
	AgentID string
	Grants  []Grant
}

type Grant struct {
	SpaceID string
	Scopes  map[Scope]struct{}
	Labels  map[string]string
}

func AllActions() []Action {
	return append([]Action(nil), allActions...)
}

func AllScopes() []Scope {
	return append([]Scope(nil), allScopes...)
}

func DecisionForHuman(
	principal HumanPrincipal,
	resource Resource,
	action Action,
) Decision {
	if !knownAction(action) {
		return Decision{Reason: CodeInvalidAction}
	}
	if principal.Session.UserID == "" || principal.Session.SessionID == "" {
		return Decision{Reason: CodeUnauthenticated}
	}
	if principal.SystemRole == identity.SystemRoleOwner {
		return allowed()
	}
	if action == CreateSpace || action == ListSpaces {
		return allowed()
	}
	if principal.SystemRole == identity.SystemRoleAdmin && systemAdminAllows(action) {
		return allowed()
	}
	if !spaceScopedAction(action) {
		return forbidden()
	}
	if resource.SpaceID == "" {
		return concealed()
	}
	role, ok := principal.SpaceRoles[resource.SpaceID]
	if !ok {
		return concealed()
	}
	if roleAllows(role, action) {
		return allowed()
	}
	return forbidden()
}

func DecisionForAgent(
	principal AgentPrincipal,
	resource Resource,
	action Action,
) Decision {
	if principal.AgentID == "" {
		return Decision{Reason: CodeUnauthenticated}
	}
	scope, scoped := scopeForAction(action)
	if !knownAction(action) || !scoped || resource.SpaceID == "" {
		return concealed()
	}
	for _, grant := range principal.Grants {
		if grant.SpaceID != resource.SpaceID {
			continue
		}
		if _, ok := grant.Scopes[scope]; !ok {
			continue
		}
		if labelsMatch(grant.Labels, resource.Labels) {
			return allowed()
		}
	}
	return concealed()
}

func knownAction(action Action) bool {
	for _, candidate := range allActions {
		if action == candidate {
			return true
		}
	}
	return false
}

func spaceScopedAction(action Action) bool {
	switch action {
	case ListCredential, ReadCredential, CreateCredential, UpdateCredential,
		DeleteCredential, RestoreCredential, PurgeCredential, GenerateTOTP,
		ListAsset, ReadAsset, CreateAsset, UpdateAsset, DeleteAsset, LinkCredential,
		ListMembers, ManageMembers, AddMember, ChangeMemberRole, RemoveMember,
		ListAgents, ReadAgent, CreateAgent, UpdateAgent, DeleteAgent,
		IssueAgentToken, RevokeAgentToken, ManageAgentGrants,
		ListAuditEvents, PurgeAuditEvents:
		return true
	default:
		return false
	}
}

func systemAdminAllows(action Action) bool {
	switch action {
	case RestoreCredential, ListAuditEvents, PurgeAuditEvents,
		ListBackups, CreateBackup, RestoreBackup,
		ReadSettings, UpdateSettings, ManageUsers, ReadHealth:
		return true
	default:
		return false
	}
}

func roleAllows(role Role, action Action) bool {
	switch role {
	case RoleOwner:
		switch action {
		case PurgeCredential, PurgeAuditEvents:
			return false
		default:
			return spaceScopedAction(action)
		}
	case RoleEditor:
		switch action {
		case ListCredential, ReadCredential, CreateCredential, UpdateCredential,
			DeleteCredential, GenerateTOTP,
			ListAsset, ReadAsset, CreateAsset, UpdateAsset, DeleteAsset,
			LinkCredential, ListMembers:
			return true
		default:
			return false
		}
	case RoleReader:
		switch action {
		case ListCredential, ReadCredential, GenerateTOTP,
			ListAsset, ReadAsset, ListMembers:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func scopeForAction(action Action) (Scope, bool) {
	switch action {
	case ListCredential:
		return ScopeCredentialList, true
	case ReadCredential, GenerateTOTP:
		return ScopeCredentialRead, true
	case CreateCredential:
		return ScopeCredentialCreate, true
	case UpdateCredential:
		return ScopeCredentialUpdate, true
	case DeleteCredential:
		return ScopeCredentialDelete, true
	case ListAsset:
		return ScopeAssetList, true
	case ReadAsset:
		return ScopeAssetRead, true
	default:
		return "", false
	}
}

func labelsMatch(required, actual map[string]string) bool {
	for key, value := range required {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func allowed() Decision {
	return Decision{Allowed: true, Reason: CodeAllowed}
}

func forbidden() Decision {
	return Decision{Reason: CodeForbidden}
}

func concealed() Decision {
	return Decision{Conceal: true, Reason: CodeConcealedNotFound}
}
