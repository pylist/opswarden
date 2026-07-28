package httpapi

import (
	"sync"
	"time"
)

const (
	anonymousFailureWindow         = time.Minute
	anonymousFailurePerKeyLimit    = 5
	anonymousFailureDurableLimit   = 32
	anonymousFailureMaxKeys        = 4096
	anonymousFailureOtherOperation = "auth.other"
)

type anonymousFailureOperationState struct {
	windowStart time.Time
	entries     map[string]uint8
	durableRows int
	suppressed  uint64
}

type anonymousFailureObservation struct {
	recordIndividual bool
	rateLimited      bool
	retryAfter       time.Duration
	aggregateCount   uint64
	aggregateStart   time.Time
	workUnits        int
}

type anonymousFailureGate struct {
	mu         sync.Mutex
	operations map[string]*anonymousFailureOperationState
}

func newAnonymousFailureGate() *anonymousFailureGate {
	return &anonymousFailureGate{
		operations: make(map[string]*anonymousFailureOperationState, 8),
	}
}

func (gate *anonymousFailureGate) observe(
	operation string,
	key string,
	now time.Time,
) anonymousFailureObservation {
	return gate.observeMode(operation, key, now, false)
}

func (gate *anonymousFailureGate) suppress(
	operation string,
	key string,
	now time.Time,
) anonymousFailureObservation {
	return gate.observeMode(operation, key, now, true)
}

func (gate *anonymousFailureGate) observeMode(
	operation string,
	key string,
	now time.Time,
	forceSuppressed bool,
) anonymousFailureObservation {
	if gate == nil || key == "" || now.IsZero() {
		return anonymousFailureObservation{rateLimited: true, workUnits: 1}
	}
	operation = boundedAuthenticationFailureOperation(operation)
	now = now.UTC()
	gate.mu.Lock()
	defer gate.mu.Unlock()

	state := gate.operations[operation]
	if state == nil {
		state = &anonymousFailureOperationState{
			windowStart: now,
			entries:     make(map[string]uint8),
		}
		gate.operations[operation] = state
	}
	observation := anonymousFailureObservation{workUnits: 1}
	if now.Before(state.windowStart) {
		observation.rateLimited = true
		observation.retryAfter = state.windowStart.Sub(now)
		return observation
	}
	if now.Sub(state.windowStart) >= anonymousFailureWindow {
		observation.aggregateCount = state.suppressed
		observation.aggregateStart = state.windowStart
		replacement := &anonymousFailureOperationState{
			windowStart: now,
			entries:     make(map[string]uint8),
		}
		if observation.aggregateCount > 0 {
			replacement.durableRows = 1
		}
		gate.operations[operation] = replacement
		state = replacement
		observation.workUnits++
	}
	if forceSuppressed {
		state.suppressed++
		observation.rateLimited = true
		observation.retryAfter = failureRetryAfter(state.windowStart, now)
		return observation
	}

	recorded, exists := state.entries[key]
	if !exists {
		if len(state.entries) >= anonymousFailureMaxKeys {
			state.suppressed++
			observation.rateLimited = true
			observation.retryAfter = failureRetryAfter(state.windowStart, now)
			return observation
		}
		state.entries[key] = 0
	}
	if int(recorded) >= anonymousFailurePerKeyLimit ||
		state.durableRows >= anonymousFailureDurableLimit {
		state.suppressed++
		observation.rateLimited = true
		observation.retryAfter = failureRetryAfter(state.windowStart, now)
		return observation
	}
	state.entries[key] = recorded + 1
	state.durableRows++
	observation.recordIndividual = true
	return observation
}

func (gate *anonymousFailureGate) entryCount(operation string) int {
	if gate == nil {
		return 0
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	state := gate.operations[boundedAuthenticationFailureOperation(operation)]
	if state == nil {
		return 0
	}
	return len(state.entries)
}

func boundedAuthenticationFailureOperation(operation string) string {
	switch operation {
	case "auth.jwt", "auth.agent", "auth.password", "auth.totp",
		"auth.refresh", "auth.logout", "auth.totp.reverify":
		return operation
	default:
		return anonymousFailureOtherOperation
	}
}

func failureRetryAfter(windowStart, now time.Time) time.Duration {
	retryAfter := anonymousFailureWindow - now.Sub(windowStart)
	if retryAfter <= 0 {
		return time.Second
	}
	return retryAfter
}
