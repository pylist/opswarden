package httpapi

import (
	"fmt"
	"testing"
	"time"
)

func TestAuthenticationFailureGateBoundsRotatingSourcesPerOperation(t *testing.T) {
	gate := newAnonymousFailureGate()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	recorded := 0
	const attempts = anonymousFailureMaxKeys + 1024
	for index := range attempts {
		observation := gate.observe(
			"auth.jwt", fmt.Sprintf("source-%d", index), now,
		)
		if observation.recordIndividual {
			recorded++
		}
		if observation.workUnits > 2 {
			t.Fatalf("observation scanned key map: %+v", observation)
		}
	}
	if recorded != anonymousFailureDurableLimit {
		t.Fatalf(
			"individual rows=%d want global budget %d",
			recorded, anonymousFailureDurableLimit,
		)
	}
	if entries := gate.entryCount("auth.jwt"); entries != anonymousFailureMaxKeys {
		t.Fatalf("entries=%d want fixed cap %d", entries, anonymousFailureMaxKeys)
	}
	gate.mu.Lock()
	_, retained := gate.operations["auth.jwt"].entries["source-0"]
	gate.mu.Unlock()
	if !retained {
		t.Fatal("overflow evicted an established key and could reset its allowance")
	}
	if gate.observe("auth.jwt", "new-rotating-source", now).recordIndividual {
		t.Fatal("overflow source received a fresh individual audit allowance")
	}

	agentRecorded := 0
	for index := range anonymousFailureDurableLimit {
		if gate.observe(
			"auth.agent", fmt.Sprintf("agent-source-%d", index), now,
		).recordIndividual {
			agentRecorded++
		}
	}
	if agentRecorded != anonymousFailureDurableLimit {
		t.Fatalf("one operation blocked another: rows=%d", agentRecorded)
	}
}

func TestAuthenticationFailureGateRolloverHasOneBudgetedAggregate(t *testing.T) {
	gate := newAnonymousFailureGate()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	for index := range anonymousFailureDurableLimit + 11 {
		gate.observe("auth.jwt", fmt.Sprintf("source-%d", index), now)
	}
	rollover := gate.observe(
		"auth.jwt", "next-window-source", now.Add(anonymousFailureWindow),
	)
	if rollover.aggregateCount != 11 || !rollover.recordIndividual ||
		rollover.rateLimited {
		t.Fatalf("rollover=%+v", rollover)
	}
	rows := 1
	if rollover.recordIndividual {
		rows++
	}
	for index := 1; index < anonymousFailureDurableLimit; index++ {
		observation := gate.observe(
			"auth.jwt", fmt.Sprintf("next-window-%d", index),
			now.Add(anonymousFailureWindow),
		)
		if observation.aggregateCount != 0 {
			t.Fatalf("duplicate aggregate in one window: %+v", observation)
		}
		if observation.recordIndividual {
			rows++
		}
	}
	if rows != anonymousFailureDurableLimit {
		t.Fatalf("durable rows=%d want strict budget %d", rows, anonymousFailureDurableLimit)
	}
}

func TestAuthenticationFailureGateSuppressionNeverRequestsIndividualAudit(t *testing.T) {
	gate := newAnonymousFailureGate()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	for range 9 {
		observation := gate.suppress("auth.totp.reverify", "session", now)
		if observation.recordIndividual || !observation.rateLimited {
			t.Fatalf("suppressed observation=%+v", observation)
		}
	}
	rollover := gate.suppress(
		"auth.totp.reverify", "session", now.Add(anonymousFailureWindow),
	)
	if rollover.aggregateCount != 9 || rollover.recordIndividual {
		t.Fatalf("suppressed rollover=%+v", rollover)
	}
}
