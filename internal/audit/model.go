package audit

import (
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxAuditTextBytes = 512

type ActorType string

const (
	ActorUser      ActorType = "user"
	ActorAgent     ActorType = "agent"
	ActorAnonymous ActorType = "anonymous"
)

const (
	FieldDisplayName    = "display_name"
	FieldTags           = "tags"
	FieldAssetLinks     = "asset_links"
	FieldCredentialType = "credential_type"
	FieldExpiresAt      = "expires_at"
	FieldDeletedAt      = "deleted_at"
	FieldName           = "name"
	FieldDescription    = "description"
	FieldRole           = "role"
	FieldSpaceGrants    = "space_grants"
	FieldTokenStatus    = "token_status"
	FieldSystemRole     = "system_role"
	FieldVersion        = "version"
)

var (
	ErrInvalidAuditEvent   = errors.New("invalid audit event")
	ErrInvalidActor        = errors.New("invalid audit actor")
	ErrInvalidSourceIP     = errors.New("invalid audit source IP")
	ErrInvalidAuditText    = errors.New("invalid audit text")
	ErrInvalidChangeField  = errors.New("invalid audit change field")
	ErrSensitiveAuditField = errors.New("sensitive audit field is forbidden")
	ErrAuditUnavailable    = errors.New("audit unavailable")
	ErrInvalidCursor       = errors.New("invalid audit cursor")
	ErrInvalidFilter       = errors.New("invalid audit filter")
)

type Actor struct {
	Type        ActorType
	ID          string
	Fingerprint string
}

type ChangeFields []string

type Event struct {
	ID           string
	RequestID    string
	CreatedAt    time.Time
	Actor        Actor
	Action       string
	SpaceID      string
	ResourceType string
	ResourceID   string
	SourceIP     string
	UserAgent    string
	Success      bool
	ErrorCode    string
	ChangeFields ChangeFields
	Reason       string
}

var allowedChangeFields = map[string]struct{}{
	FieldDisplayName:    {},
	FieldTags:           {},
	FieldAssetLinks:     {},
	FieldCredentialType: {},
	FieldExpiresAt:      {},
	FieldDeletedAt:      {},
	FieldName:           {},
	FieldDescription:    {},
	FieldRole:           {},
	FieldSpaceGrants:    {},
	FieldTokenStatus:    {},
	FieldSystemRole:     {},
	FieldVersion:        {},
}

var sensitiveFieldFragments = []string{
	"password",
	"secret",
	"token",
	"payload",
	"private_key",
	"seed",
	"master_key",
	"session_id",
	"connection_string",
	"old_value",
	"new_value",
	"value",
	"username",
	"api_key",
	"passphrase",
	"wrapped_data_key",
	"ciphertext",
	"nonce",
	"cookie",
	"authorization",
}

func Validate(event Event) error {
	if !validIdentifier(event.ID, 256) ||
		!validIdentifier(event.RequestID, 256) ||
		event.CreatedAt.IsZero() ||
		!validAction(event.Action) ||
		!validResourceType(event.ResourceType) ||
		(event.SpaceID != "" && !validIdentifier(event.SpaceID, 256)) ||
		(event.ResourceID != "" && !validIdentifier(event.ResourceID, 256)) {
		return ErrInvalidAuditEvent
	}
	if err := validateActor(event.Actor); err != nil {
		return err
	}
	if err := validateSourceIP(event.SourceIP); err != nil {
		return err
	}
	if !validAuditText(event.UserAgent) || !validAuditText(event.Reason) {
		return ErrInvalidAuditText
	}
	if event.Success {
		if event.ErrorCode != "" {
			return ErrInvalidAuditEvent
		}
	} else if !validErrorCode(event.ErrorCode) {
		return ErrInvalidAuditEvent
	}
	return validateChangeFields(event.ChangeFields)
}

func validateActor(actor Actor) error {
	if actor.Type != ActorUser && actor.Type != ActorAgent &&
		actor.Type != ActorAnonymous {
		return ErrInvalidActor
	}
	if !validIdentifier(actor.ID, 256) {
		return ErrInvalidActor
	}
	if len(actor.Fingerprint) != 16 {
		return ErrInvalidActor
	}
	for _, character := range actor.Fingerprint {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return ErrInvalidActor
		}
	}
	return nil
}

func validateSourceIP(sourceIP string) error {
	address, err := netip.ParseAddr(sourceIP)
	if err != nil || address.Zone() != "" || address.String() != sourceIP {
		return ErrInvalidSourceIP
	}
	return nil
}

func validateChangeFields(fields ChangeFields) error {
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if _, ok := allowedChangeFields[field]; ok {
			if _, duplicate := seen[field]; duplicate {
				return ErrInvalidChangeField
			}
			seen[field] = struct{}{}
			continue
		}
		lower := strings.ToLower(field)
		for _, fragment := range sensitiveFieldFragments {
			if strings.Contains(lower, fragment) {
				return ErrSensitiveAuditField
			}
		}
		return ErrInvalidChangeField
	}
	return nil
}

func validAuditText(value string) bool {
	if len(value) > MaxAuditTextBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character <= 0x1f || (character >= 0x7f && character <= 0x9f) {
			return false
		}
	}
	return true
}

func validIdentifier(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') {
			continue
		}
		switch character {
		case '-', '_', '.', ':', '@', '/':
			continue
		default:
			return false
		}
	}
	return true
}

func validAction(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validResourceType(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			character == '_' {
			continue
		}
		return false
	}
	return true
}

func validErrorCode(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '_' {
			continue
		}
		return false
	}
	return true
}
