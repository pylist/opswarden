package httpapi

import (
	"fmt"
	"testing"
	"time"
)

func TestAnonymousFailureGateIsBoundedAndFlushesOneWindowAggregate(t *testing.T) {
	gate := newAnonymousFailureGate()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	for index := range anonymousFailureMaxKeys + 100 {
		gate.observe(fmt.Sprintf("subject-%d", index), now)
	}
	if len(gate.entries) != anonymousFailureMaxKeys {
		t.Fatalf("gate entries=%d", len(gate.entries))
	}

	key := "stable-subject"
	for range anonymousFailureAuditLimit + 7 {
		gate.observe(key, now)
	}
	rollover := gate.observe(key, now.Add(anonymousFailureWindow))
	if rollover.aggregateCount != 7 || !rollover.recordIndividual ||
		rollover.rateLimited {
		t.Fatalf("rollover=%+v", rollover)
	}
	sameWindow := gate.observe(key, now.Add(anonymousFailureWindow))
	if sameWindow.aggregateCount != 0 {
		t.Fatalf("duplicate aggregate in one window: %+v", sameWindow)
	}
}
