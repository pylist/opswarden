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

	"opswarden/internal/authorization"
	"opswarden/internal/identity"
	"opswarden/internal/storage"
)

type SessionRevoker interface {
	RevokeUserSessionsTx(context.Context, *sql.Tx, string) error
}

type Service struct {
	repository repository
	revoker    SessionRevoker
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
