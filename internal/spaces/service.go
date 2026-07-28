package spaces

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"opswarden/internal/audit"
	"opswarden/internal/authorization"
	"opswarden/internal/identity"
	"opswarden/internal/platform"
	"opswarden/internal/storage"
)

type SessionRevoker interface {
	RevokeUserSessionsTx(context.Context, *sql.Tx, string) error
}

type AuditAppender interface {
	AppendTx(context.Context, *sql.Tx, audit.Event) error
}

type Service struct {
	repository repository
	revoker    SessionRevoker
	audit      AuditAppender
	clock      platform.Clock
}

func NewService(db *storage.DB, revoker SessionRevoker) (*Service, error) {
	if db == nil || db.Writer == nil || db.Reader == nil {
		return nil, errors.New("Spaces database is required")
	}
	if revoker == nil {
		return nil, errors.New("Spaces session revoker is required")
	}
	return &Service{
		repository: repository{db: db},
		revoker:    revoker,
	}, nil
}

func NewAuditedService(
	db *storage.DB,
	revoker SessionRevoker,
	auditAppender AuditAppender,
	clock platform.Clock,
) (*Service, error) {
	service, err := NewService(db, revoker)
	if err != nil {
		return nil, err
	}
	if auditAppender == nil {
		return nil, errors.New("Spaces audit appender is required")
	}
	if clock == nil {
		return nil, errors.New("Spaces clock is required")
	}
	service.audit = auditAppender
	service.clock = clock
	return service, nil
}

func (s *Service) Create(
	ctx context.Context,
	principal identity.SessionPrincipal,
	input CreateInput,
) (Space, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return Space{}, ErrInvalidName
	}
	id, err := randomID()
	if err != nil {
		return Space{}, err
	}
	now := time.Now().UTC()
	space := Space{
		ID: id, Name: name, Role: Owner, CreatedAt: now, UpdatedAt: now,
	}
	err = s.repository.withTx(ctx, func(tx *sql.Tx) error {
		human, err := s.repository.humanPrincipalTx(ctx, tx, principal, "")
		if err != nil {
			return err
		}
		if err := decisionError(authorization.DecisionForHuman(
			human, authorization.Resource{}, authorization.CreateSpace,
		)); err != nil {
			return err
		}
		return s.repository.createTx(ctx, tx, space, principal.UserID)
	})
	if err != nil {
		return Space{}, err
	}
	return space, nil
}

func (s *Service) CreateAudited(
	ctx context.Context,
	mutation MutationContext,
	input CreateInput,
) (Space, error) {
	if s.audit == nil || s.clock == nil {
		return Space{}, audit.ErrAuditUnavailable
	}
	if mutation.Session.UserID == "" || mutation.Session.SessionID == "" ||
		mutation.Actor.Type != audit.ActorUser ||
		mutation.Actor.ID != mutation.Session.UserID {
		return Space{}, ErrUnauthenticated
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return Space{}, ErrInvalidName
	}
	id, err := randomID()
	if err != nil {
		return Space{}, err
	}
	now := s.clock.Now().UTC()
	if now.IsZero() {
		return Space{}, ErrInvalidName
	}
	space := Space{
		ID: id, Name: name, Role: Owner, CreatedAt: now, UpdatedAt: now,
	}
	err = s.repository.withTx(ctx, func(tx *sql.Tx) error {
		human, err := s.repository.humanPrincipalTx(
			ctx, tx, mutation.Session, "",
		)
		if err != nil {
			return err
		}
		if err := decisionError(authorization.DecisionForHuman(
			human, authorization.Resource{}, authorization.CreateSpace,
		)); err != nil {
			return err
		}
		if err := s.repository.createTx(
			ctx, tx, space, mutation.Session.UserID,
		); err != nil {
			return err
		}
		eventID, err := randomID()
		if err != nil {
			return audit.ErrAuditUnavailable
		}
		event := audit.Event{
			ID:        strings.Replace(eventID, "spc_", "aud_", 1),
			RequestID: mutation.RequestID, CreatedAt: now,
			Actor: mutation.Actor, Action: "space.create", SpaceID: space.ID,
			ResourceType: "space", ResourceID: space.ID,
			SourceIP: mutation.SourceIP, UserAgent: mutation.UserAgent,
			Success: true, ChangeFields: audit.ChangeFields{audit.FieldName},
		}
		if err := s.audit.AppendTx(ctx, tx, event); err != nil {
			return audit.ErrAuditUnavailable
		}
		return nil
	})
	if err != nil {
		return Space{}, err
	}
	return space, nil
}

func (s *Service) AddMember(
	ctx context.Context,
	principal identity.SessionPrincipal,
	spaceID, userID string,
	role Role,
) error {
	if !role.Valid() {
		return ErrInvalidRole
	}
	if spaceID == "" {
		return ErrNotFound
	}
	if userID == "" {
		return ErrUserNotFound
	}
	return s.repository.withTx(ctx, func(tx *sql.Tx) error {
		if err := s.repository.requireActiveSpaceTx(ctx, tx, spaceID); err != nil {
			return err
		}
		if err := s.authorizeMemberManagement(
			ctx, tx, principal, spaceID, authorization.AddMember,
		); err != nil {
			return err
		}
		exists, err := s.repository.activeUserExistsTx(ctx, tx, userID)
		if err != nil {
			return err
		}
		if !exists {
			return ErrUserNotFound
		}
		return s.repository.addMembershipTx(
			ctx, tx, spaceID, userID, role, time.Now().UTC(),
		)
	})
}

func (s *Service) ChangeRole(
	ctx context.Context,
	principal identity.SessionPrincipal,
	spaceID, userID string,
	role Role,
) error {
	if !role.Valid() {
		return ErrInvalidRole
	}
	if spaceID == "" {
		return ErrNotFound
	}
	if userID == "" {
		return ErrMembershipNotFound
	}
	return s.repository.withTx(ctx, func(tx *sql.Tx) error {
		if err := s.repository.requireActiveSpaceTx(ctx, tx, spaceID); err != nil {
			return err
		}
		if err := s.authorizeMemberManagement(
			ctx, tx, principal, spaceID, authorization.ChangeMemberRole,
		); err != nil {
			return err
		}
		currentRole, err := s.repository.membershipRoleTx(ctx, tx, spaceID, userID)
		if err != nil {
			return err
		}
		if currentRole == role {
			return nil
		}
		if currentRole == Owner && role != Owner {
			if err := s.requireAnotherOwner(ctx, tx, spaceID, userID); err != nil {
				return err
			}
		}
		if err := s.repository.changeMembershipRoleTx(
			ctx, tx, spaceID, userID, role,
		); err != nil {
			return err
		}
		return s.revoker.RevokeUserSessionsTx(ctx, tx, userID)
	})
}

func (s *Service) RemoveMember(
	ctx context.Context,
	principal identity.SessionPrincipal,
	spaceID, userID string,
) error {
	if spaceID == "" {
		return ErrNotFound
	}
	if userID == "" {
		return ErrMembershipNotFound
	}
	return s.repository.withTx(ctx, func(tx *sql.Tx) error {
		if err := s.repository.requireActiveSpaceTx(ctx, tx, spaceID); err != nil {
			return err
		}
		if err := s.authorizeMemberManagement(
			ctx, tx, principal, spaceID, authorization.RemoveMember,
		); err != nil {
			return err
		}
		role, err := s.repository.membershipRoleTx(ctx, tx, spaceID, userID)
		if err != nil {
			return err
		}
		if role == Owner {
			if err := s.requireAnotherOwner(ctx, tx, spaceID, userID); err != nil {
				return err
			}
		}
		if err := s.repository.removeMembershipTx(
			ctx, tx, spaceID, userID,
		); err != nil {
			return err
		}
		return s.revoker.RevokeUserSessionsTx(ctx, tx, userID)
	})
}

func (s *Service) ListForUser(
	ctx context.Context,
	principal identity.SessionPrincipal,
) ([]Space, error) {
	human, err := s.repository.humanPrincipal(ctx, principal)
	if err != nil {
		return nil, err
	}
	if err := decisionError(authorization.DecisionForHuman(
		human, authorization.Resource{}, authorization.ListSpaces,
	)); err != nil {
		return nil, err
	}
	return s.repository.listForUser(
		ctx,
		principal.UserID,
		human.SystemRole == identity.SystemRoleOwner,
	)
}

// ResolveAuthorizationPrincipal builds a fresh authorization view for one
// request. Callers must not cache the result across requests because user and
// Space roles can change while a server-side session remains active.
func (s *Service) ResolveAuthorizationPrincipal(
	ctx context.Context,
	session identity.SessionPrincipal,
	spaceID string,
) (authorization.HumanPrincipal, error) {
	var principal authorization.HumanPrincipal
	err := s.repository.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		principal, err = s.repository.humanPrincipalTx(ctx, tx, session, spaceID)
		return err
	})
	return principal, err
}

func (s *Service) authorizeMemberManagement(
	ctx context.Context,
	tx *sql.Tx,
	principal identity.SessionPrincipal,
	spaceID string,
	action authorization.Action,
) error {
	human, err := s.repository.humanPrincipalTx(ctx, tx, principal, spaceID)
	if err != nil {
		return err
	}
	return decisionError(authorization.DecisionForHuman(
		human,
		authorization.Resource{SpaceID: spaceID},
		action,
	))
}

func (s *Service) requireAnotherOwner(
	ctx context.Context,
	tx *sql.Tx,
	spaceID, excludedUserID string,
) error {
	count, err := s.repository.remainingOwnerCountTx(
		ctx, tx, spaceID, excludedUserID,
	)
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrLastOwner
	}
	return nil
}

func decisionError(decision authorization.Decision) error {
	switch err := decision.Err(); {
	case err == nil:
		return nil
	case errors.Is(err, authorization.ErrUnauthenticated):
		return ErrUnauthenticated
	case errors.Is(err, authorization.ErrNotFound):
		return ErrNotFound
	default:
		return ErrForbidden
	}
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate Space ID: %w", err)
	}
	return "spc_" + hex.EncodeToString(raw[:]), nil
}
