package audit

import (
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
