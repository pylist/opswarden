package httpapi

import (
	"sync"
	"time"
)

const (
	anonymousFailureWindow     = time.Minute
	anonymousFailureAuditLimit = 5
	anonymousFailureMaxKeys    = 4096
)

type anonymousFailureState struct {
	windowStart time.Time
	lastSeen    time.Time
	recorded    int
	suppressed  uint64
}

type anonymousFailureObservation struct {
	recordIndividual bool
	rateLimited      bool
	retryAfter       time.Duration
	aggregateCount   uint64
	aggregateStart   time.Time
}

type anonymousFailureGate struct {
	mu      sync.Mutex
	entries map[string]*anonymousFailureState
}

func newAnonymousFailureGate() *anonymousFailureGate {
	return &anonymousFailureGate{
		entries: make(map[string]*anonymousFailureState),
	}
}

func (gate *anonymousFailureGate) observe(
	key string,
	now time.Time,
) anonymousFailureObservation {
	if gate == nil || key == "" || now.IsZero() {
		return anonymousFailureObservation{rateLimited: true}
	}
	now = now.UTC()
	gate.mu.Lock()
	defer gate.mu.Unlock()
	state := gate.entries[key]
	if state == nil {
		if len(gate.entries) >= anonymousFailureMaxKeys {
			gate.evictOldestLocked()
		}
		state = &anonymousFailureState{windowStart: now}
		gate.entries[key] = state
	}
	if now.Before(state.windowStart) {
		return anonymousFailureObservation{
			rateLimited: true, retryAfter: state.windowStart.Sub(now),
		}
	}
	observation := anonymousFailureObservation{}
	if now.Sub(state.windowStart) >= anonymousFailureWindow {
		observation.aggregateCount = state.suppressed
		observation.aggregateStart = state.windowStart
		state.windowStart = now
		state.recorded = 0
		state.suppressed = 0
	}
	state.lastSeen = now
	if state.recorded < anonymousFailureAuditLimit {
		state.recorded++
		observation.recordIndividual = true
		return observation
	}
	state.suppressed++
	observation.rateLimited = true
	observation.retryAfter = anonymousFailureWindow - now.Sub(state.windowStart)
	if observation.retryAfter <= 0 {
		observation.retryAfter = time.Second
	}
	return observation
}

func (gate *anonymousFailureGate) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for key, state := range gate.entries {
		if oldestKey == "" || state.lastSeen.Before(oldest) ||
			(state.lastSeen.Equal(oldest) && key < oldestKey) {
			oldestKey = key
			oldest = state.lastSeen
		}
	}
	if oldestKey != "" {
		delete(gate.entries, oldestKey)
	}
}
