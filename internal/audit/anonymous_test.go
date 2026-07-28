package audit

import (
	"errors"
	"testing"
	"time"
)

func TestValidateAllowsBoundedAnonymousAuthenticationActor(t *testing.T) {
	event := Event{
		ID: "aud_anonymous", RequestID: "req_anonymous",
		CreatedAt: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
		Actor: Actor{
			Type: ActorAnonymous, ID: "anonymous",
			Fingerprint: "0123456789abcdef",
		},
		Action: "auth.password", ResourceType: "authentication",
		SourceIP: "198.51.100.10", Success: false,
		ErrorCode: "INVALID_CREDENTIALS",
	}
	if err := Validate(event); err != nil {
		t.Fatalf("validate anonymous authentication event: %v", err)
	}
}

func TestValidateAllowsDedicatedSystemMaintenanceActor(t *testing.T) {
	event := Event{
		ID: "aud_maintenance", RequestID: "mnt_20260729",
		CreatedAt: time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
		Actor: Actor{
			Type: ActorSystem, ID: SystemMaintenanceActorID,
			Fingerprint: SystemMaintenanceFingerprint,
		},
		Action: "credential.purge", ResourceType: "credential",
		ResourceID: "cred_old", SourceIP: "0.0.0.0", Success: true,
		ChangeFields: ChangeFields{FieldDeletedAt},
	}
	if err := Validate(event); err != nil {
		t.Fatalf("validate system maintenance event: %v", err)
	}
}

func TestValidateRejectsImpersonatedSystemActor(t *testing.T) {
	event := Event{
		ID: "aud_system_invalid", RequestID: "req_system_invalid",
		CreatedAt: time.Now().UTC(),
		Actor: Actor{
			Type: ActorSystem, ID: "operator",
			Fingerprint: SystemMaintenanceFingerprint,
		},
		Action: "credential.purge", ResourceType: "credential",
		ResourceID: "cred_test", SourceIP: "0.0.0.0", Success: true,
		ChangeFields: ChangeFields{FieldDeletedAt},
	}
	if err := Validate(event); !errors.Is(err, ErrInvalidActor) {
		t.Fatalf("err=%v", err)
	}
}

func TestAnonymousAuthenticationOutcomeIsDurableAndListable(t *testing.T) {
	h := newAuditHarness(t)
	event := Event{
		ID: "aud_anonymous", RequestID: "req_anonymous",
		CreatedAt: h.now,
		Actor: Actor{
			Type: ActorAnonymous, ID: "anonymous",
			Fingerprint: "0123456789abcdef",
		},
		Action: "auth.password", ResourceType: "authentication",
		SourceIP: "198.51.100.10", Success: false,
		ErrorCode: "INVALID_CREDENTIALS",
	}
	if err := h.service.RecordReadBeforeReturn(h.ctx, event); err != nil {
		t.Fatal(err)
	}
	events, _, err := h.service.List(h.ctx, Filter{
		ActorType: ActorAnonymous,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != event.ID ||
		events[0].Actor.ID != "anonymous" ||
		events[0].ErrorCode != "INVALID_CREDENTIALS" {
		t.Fatalf("anonymous events=%+v", events)
	}
}

func TestSystemMaintenanceOutcomeIsDurableAndFilterable(t *testing.T) {
	h := newAuditHarness(t)
	event := Event{
		ID: "aud_system", RequestID: "mnt_20260729",
		CreatedAt: h.now,
		Actor: Actor{
			Type: ActorSystem, ID: SystemMaintenanceActorID,
			Fingerprint: SystemMaintenanceFingerprint,
		},
		Action: "credential.purge", ResourceType: "credential",
		ResourceID: "cred_old", SourceIP: "0.0.0.0", Success: true,
		ChangeFields: ChangeFields{FieldDeletedAt},
	}
	if err := h.service.RecordReadBeforeReturn(h.ctx, event); err != nil {
		t.Fatal(err)
	}
	events, _, err := h.service.List(h.ctx, Filter{
		ActorType: ActorSystem,
		ActorID:   SystemMaintenanceActorID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Actor != event.Actor ||
		events[0].RequestID != event.RequestID {
		t.Fatalf("system events=%+v", events)
	}
	events, _, err = h.service.List(h.ctx, Filter{
		ActorType: ActorSystem, ActorID: "operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("impersonated system actor matched=%+v", events)
	}
}
