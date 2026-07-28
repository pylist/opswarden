package agents

import (
	"math"
	"sync"
	"time"
)

type Operation string

const (
	OperationAuthFailure                Operation = "auth_failure"
	OperationBootstrap                  Operation = "bootstrap"
	OperationLoginSource                Operation = "login_source"
	OperationReverifySource             Operation = "reverify_source"
	OperationReverifyPrincipal          Operation = "reverify_principal"
	OperationHumanRequestReadSource     Operation = "human_request_read_source"
	OperationHumanRequestWriteSource    Operation = "human_request_write_source"
	OperationAgentRequestReadSource     Operation = "agent_request_read_source"
	OperationAgentRequestWriteSource    Operation = "agent_request_write_source"
	OperationHumanCredentialListSource  Operation = "human_credential_list_source"
	OperationHumanCredentialReadSource  Operation = "human_credential_read_source"
	OperationHumanCredentialWriteSource Operation = "human_credential_write_source"
	OperationAgentCredentialListSource  Operation = "agent_credential_list_source"
	OperationAgentCredentialReadSource  Operation = "agent_credential_read_source"
	OperationAgentCredentialWriteSource Operation = "agent_credential_write_source"
	OperationHumanRequestRead           Operation = "human_request_read"
	OperationHumanRequestWrite          Operation = "human_request_write"
	OperationAgentRequestRead           Operation = "agent_request_read"
	OperationAgentRequestWrite          Operation = "agent_request_write"
	OperationHumanCredentialList        Operation = "human_credential_list"
	OperationHumanCredentialRead        Operation = "human_credential_read"
	OperationHumanCredentialWrite       Operation = "human_credential_write"
	OperationAgentCredentialList        Operation = "agent_credential_list"
	OperationAgentCredentialRead        Operation = "agent_credential_read"
	OperationAgentCredentialWrite       Operation = "agent_credential_write"
)

var allOperations = []Operation{
	OperationAuthFailure,
	OperationBootstrap,
	OperationLoginSource,
	OperationReverifySource,
	OperationReverifyPrincipal,
	OperationHumanRequestReadSource,
	OperationHumanRequestWriteSource,
	OperationAgentRequestReadSource,
	OperationAgentRequestWriteSource,
	OperationHumanCredentialListSource,
	OperationHumanCredentialReadSource,
	OperationHumanCredentialWriteSource,
	OperationAgentCredentialListSource,
	OperationAgentCredentialReadSource,
	OperationAgentCredentialWriteSource,
	OperationHumanRequestRead,
	OperationHumanRequestWrite,
	OperationAgentRequestRead,
	OperationAgentRequestWrite,
	OperationHumanCredentialList,
	OperationHumanCredentialRead,
	OperationHumanCredentialWrite,
	OperationAgentCredentialList,
	OperationAgentCredentialRead,
	OperationAgentCredentialWrite,
}

type LimiterConfig struct {
	Capacity        map[Operation]int
	RefillPerSecond map[Operation]float64
	MaxSubjects     int
	// GenerationTTL sets the generation phase length. Inactive state receives
	// one previous-generation grace phase before reclamation. Each operation
	// clamps it to at least its capacity/refill full-recovery duration.
	GenerationTTL time.Duration
}

type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
}

type LimitRequest struct {
	Subject   string
	Operation Operation
}

type Reservation struct {
	mu       sync.Mutex
	limiter  *Limiter
	items    []reservationItem
	resolved bool
}

type reservationItem struct {
	subject    string
	operation  Operation
	overflow   bool
	units      float64
	generation uint64
}

func (reservation *Reservation) Commit() {
	if reservation == nil {
		return
	}
	reservation.mu.Lock()
	reservation.resolved = true
	reservation.mu.Unlock()
}

func (reservation *Reservation) Refund(now time.Time) {
	if reservation == nil {
		return
	}
	reservation.mu.Lock()
	if reservation.resolved {
		reservation.mu.Unlock()
		return
	}
	reservation.resolved = true
	reservation.mu.Unlock()
	reservation.limiter.refundMany(reservation.items, now)
}

type limiterBucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

type Limiter struct {
	mu               sync.Mutex
	capacity         map[Operation]float64
	refill           map[Operation]float64
	maxSubjects      int
	buckets          map[Operation]map[string]*limiterBucket
	previousBuckets  map[Operation]map[string]*limiterBucket
	overflow         map[Operation]*limiterBucket
	previousOverflow map[Operation]*limiterBucket
	lastNow          map[Operation]time.Time
	workUnits        map[Operation]uint64
	generationTTL    map[Operation]time.Duration
	generationStart  map[Operation]time.Time
	generation       map[Operation]uint64
}

func NewLimiter(config LimiterConfig) *Limiter {
	if config.MaxSubjects <= 0 {
		config.MaxSubjects = 10_000
	}
	if config.GenerationTTL <= 0 {
		config.GenerationTTL = 15 * time.Minute
	}
	limiter := &Limiter{
		capacity:         make(map[Operation]float64, len(allOperations)),
		refill:           make(map[Operation]float64, len(allOperations)),
		maxSubjects:      config.MaxSubjects,
		buckets:          make(map[Operation]map[string]*limiterBucket),
		previousBuckets:  make(map[Operation]map[string]*limiterBucket),
		overflow:         make(map[Operation]*limiterBucket),
		previousOverflow: make(map[Operation]*limiterBucket),
		lastNow:          make(map[Operation]time.Time),
		workUnits:        make(map[Operation]uint64),
		generationTTL:    make(map[Operation]time.Duration, len(allOperations)),
		generationStart:  make(map[Operation]time.Time, len(allOperations)),
		generation:       make(map[Operation]uint64, len(allOperations)),
	}
	defaultCapacity := map[Operation]int{
		OperationAuthFailure:                5,
		OperationBootstrap:                  2,
		OperationLoginSource:                20,
		OperationReverifySource:             10,
		OperationReverifyPrincipal:          5,
		OperationHumanRequestReadSource:     200,
		OperationHumanRequestWriteSource:    200,
		OperationAgentRequestReadSource:     200,
		OperationAgentRequestWriteSource:    200,
		OperationHumanCredentialListSource:  200,
		OperationHumanCredentialReadSource:  200,
		OperationHumanCredentialWriteSource: 200,
		OperationAgentCredentialListSource:  200,
		OperationAgentCredentialReadSource:  200,
		OperationAgentCredentialWriteSource: 200,
		OperationHumanRequestRead:           120,
		OperationHumanRequestWrite:          60,
		OperationAgentRequestRead:           120,
		OperationAgentRequestWrite:          60,
		OperationHumanCredentialList:        60,
		OperationHumanCredentialRead:        30,
		OperationHumanCredentialWrite:       20,
		OperationAgentCredentialList:        60,
		OperationAgentCredentialRead:        30,
		OperationAgentCredentialWrite:       20,
	}
	defaultRefill := map[Operation]float64{
		OperationAuthFailure:                1.0 / 60,
		OperationBootstrap:                  1.0 / 60,
		OperationLoginSource:                1.0 / 6,
		OperationReverifySource:             1.0 / 30,
		OperationReverifyPrincipal:          1.0 / 60,
		OperationHumanRequestReadSource:     10,
		OperationHumanRequestWriteSource:    10,
		OperationAgentRequestReadSource:     10,
		OperationAgentRequestWriteSource:    10,
		OperationHumanCredentialListSource:  10,
		OperationHumanCredentialReadSource:  10,
		OperationHumanCredentialWriteSource: 10,
		OperationAgentCredentialListSource:  10,
		OperationAgentCredentialReadSource:  10,
		OperationAgentCredentialWriteSource: 10,
		OperationHumanRequestRead:           2,
		OperationHumanRequestWrite:          1,
		OperationAgentRequestRead:           2,
		OperationAgentRequestWrite:          1,
		OperationHumanCredentialList:        1,
		OperationHumanCredentialRead:        0.5,
		OperationHumanCredentialWrite:       1.0 / 3,
		OperationAgentCredentialList:        1,
		OperationAgentCredentialRead:        0.5,
		OperationAgentCredentialWrite:       1.0 / 3,
	}
	for _, operation := range allOperations {
		capacity := config.Capacity[operation]
		if capacity <= 0 {
			capacity = defaultCapacity[operation]
		}
		refill := config.RefillPerSecond[operation]
		if refill <= 0 || math.IsNaN(refill) || math.IsInf(refill, 0) {
			refill = defaultRefill[operation]
		}
		limiter.capacity[operation] = float64(capacity)
		limiter.refill[operation] = refill
		limiter.generationTTL[operation] = max(
			config.GenerationTTL,
			naturalRecoveryDuration(float64(capacity), refill),
		)
		limiter.buckets[operation] = make(map[string]*limiterBucket)
		limiter.previousBuckets[operation] = make(map[string]*limiterBucket)
	}
	return limiter
}

func (limiter *Limiter) Allow(
	subject string,
	operation Operation,
	now time.Time,
) Decision {
	return limiter.decide(subject, operation, now, true)
}

// Check reports whether a subject is currently blocked without spending a
// token or creating a new subject bucket.
func (limiter *Limiter) Check(
	subject string,
	operation Operation,
	now time.Time,
) Decision {
	return limiter.decide(subject, operation, now, false)
}

func (limiter *Limiter) Reserve(
	requests []LimitRequest,
	now time.Time,
) (*Reservation, Decision) {
	if limiter == nil || len(requests) == 0 || now.IsZero() {
		return nil, Decision{}
	}
	now = now.UTC()
	unique := make([]LimitRequest, 0, len(requests))
	seen := make(map[LimitRequest]struct{}, len(requests))
	for _, request := range requests {
		if request.Subject == "" {
			return nil, Decision{}
		}
		if _, known := limiter.capacity[request.Operation]; !known {
			return nil, Decision{}
		}
		if _, duplicate := seen[request]; duplicate {
			continue
		}
		seen[request] = struct{}{}
		unique = append(unique, request)
	}

	type stagedKey struct {
		operation Operation
		subject   string
		overflow  bool
	}
	type stagedBucket struct {
		key    stagedKey
		bucket *limiterBucket
		tokens float64
		spend  float64
		create bool
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	operations := make(map[Operation]struct{}, len(unique))
	for _, request := range unique {
		if last := limiter.lastNow[request.Operation]; !last.IsZero() &&
			now.Before(last) {
			return nil, Decision{RetryAfter: last.Sub(now)}
		}
		operations[request.Operation] = struct{}{}
	}
	for operation := range operations {
		limiter.rotateGenerationLocked(operation, now)
	}
	staged := make([]stagedBucket, 0, len(unique))
	stagedIndexes := make(map[stagedKey]int, len(unique))
	pendingNew := make(map[Operation]int, len(unique))
	var retryAfter time.Duration
	for _, request := range unique {
		capacity := limiter.capacity[request.Operation]
		bucket := limiter.subjectBucketLocked(
			request.Operation, request.Subject,
		)
		limiter.workUnits[request.Operation]++
		key := stagedKey{
			operation: request.Operation,
			subject:   request.Subject,
		}
		create := false
		if bucket == nil {
			if limiter.subjectCountLocked(request.Operation)+
				pendingNew[request.Operation] < limiter.maxSubjects {
				pendingNew[request.Operation]++
				create = true
			} else {
				key.subject = ""
				key.overflow = true
				bucket = limiter.overflowBucketLocked(request.Operation)
			}
		}
		if index, exists := stagedIndexes[key]; exists {
			staged[index].spend++
			continue
		}
		tokens := capacity
		if bucket != nil {
			if now.Before(bucket.last) {
				return nil, Decision{RetryAfter: bucket.last.Sub(now)}
			}
			tokens = math.Min(
				capacity,
				bucket.tokens+
					now.Sub(bucket.last).Seconds()*limiter.refill[request.Operation],
			)
		}
		stagedIndexes[key] = len(staged)
		staged = append(staged, stagedBucket{
			key: key, bucket: bucket, tokens: tokens, spend: 1, create: create,
		})
	}
	for _, item := range staged {
		if item.tokens >= item.spend {
			continue
		}
		missing := item.spend - item.tokens
		wait := time.Duration(math.Ceil(
			missing / limiter.refill[item.key.operation] * float64(time.Second),
		))
		if wait > retryAfter {
			retryAfter = wait
		}
	}
	for _, request := range unique {
		limiter.lastNow[request.Operation] = now
	}
	if retryAfter > 0 {
		return nil, Decision{RetryAfter: retryAfter}
	}
	for index := range staged {
		item := &staged[index]
		if item.bucket == nil {
			item.bucket = &limiterBucket{}
			if item.key.overflow {
				limiter.overflow[item.key.operation] = item.bucket
			} else {
				limiter.buckets[item.key.operation][item.key.subject] = item.bucket
			}
		}
		item.bucket.tokens = item.tokens - item.spend
		item.bucket.last = now
		item.bucket.lastSeen = now
	}
	reservationItems := make([]reservationItem, 0, len(staged))
	for _, item := range staged {
		reservationItems = append(reservationItems, reservationItem{
			subject: item.key.subject, operation: item.key.operation,
			overflow: item.key.overflow, units: item.spend,
			generation: limiter.generation[item.key.operation],
		})
	}
	return &Reservation{
		limiter: limiter, items: reservationItems,
	}, Decision{Allowed: true}
}

func (limiter *Limiter) refundMany(
	items []reservationItem,
	now time.Time,
) {
	if limiter == nil || len(items) == 0 || now.IsZero() {
		return
	}
	now = now.UTC()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	for _, item := range items {
		capacity, known := limiter.capacity[item.operation]
		if !known || (!item.overflow && item.subject == "") ||
			item.units <= 0 ||
			item.generation != limiter.generation[item.operation] {
			continue
		}
		if last := limiter.lastNow[item.operation]; !last.IsZero() &&
			now.Before(last) {
			continue
		}
		var bucket *limiterBucket
		if item.overflow {
			bucket = limiter.overflow[item.operation]
		} else {
			bucket = limiter.buckets[item.operation][item.subject]
		}
		limiter.workUnits[item.operation]++
		if bucket == nil {
			continue
		}
		if !now.Before(bucket.last) {
			elapsed := now.Sub(bucket.last).Seconds()
			bucket.tokens = math.Min(
				capacity,
				bucket.tokens+elapsed*limiter.refill[item.operation],
			)
			bucket.last = now
			bucket.lastSeen = now
		}
		bucket.tokens = math.Min(capacity, bucket.tokens+item.units)
		limiter.lastNow[item.operation] = now
	}
}

func (limiter *Limiter) decide(
	subject string,
	operation Operation,
	now time.Time,
	consume bool,
) Decision {
	if limiter == nil || subject == "" || now.IsZero() {
		return Decision{}
	}
	capacity, known := limiter.capacity[operation]
	if !known {
		return Decision{}
	}
	now = now.UTC()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	if last := limiter.lastNow[operation]; !last.IsZero() && now.Before(last) {
		return Decision{RetryAfter: last.Sub(now)}
	}
	limiter.rotateGenerationLocked(operation, now)
	limiter.lastNow[operation] = now
	subjects := limiter.buckets[operation]
	bucket := limiter.subjectBucketLocked(operation, subject)
	limiter.workUnits[operation]++
	if bucket == nil {
		if !consume {
			if limiter.subjectCountLocked(operation) < limiter.maxSubjects {
				return Decision{Allowed: true}
			}
			bucket = limiter.overflowBucketLocked(operation)
			if bucket == nil {
				return Decision{Allowed: true}
			}
		} else if limiter.subjectCountLocked(operation) >= limiter.maxSubjects {
			bucket = limiter.overflowBucketLocked(operation)
			if bucket == nil {
				bucket = &limiterBucket{
					tokens: capacity, last: now, lastSeen: now,
				}
				limiter.overflow[operation] = bucket
			}
		} else {
			bucket = &limiterBucket{tokens: capacity, last: now, lastSeen: now}
			subjects[subject] = bucket
		}
	}
	if now.Before(bucket.last) {
		return Decision{RetryAfter: bucket.last.Sub(now)}
	}
	elapsed := now.Sub(bucket.last).Seconds()
	bucket.tokens = math.Min(capacity, bucket.tokens+elapsed*limiter.refill[operation])
	bucket.last = now
	bucket.lastSeen = now
	if bucket.tokens < 1 {
		missing := 1 - bucket.tokens
		return Decision{
			RetryAfter: time.Duration(math.Ceil(
				missing / limiter.refill[operation] * float64(time.Second),
			)),
		}
	}
	if consume {
		bucket.tokens--
	}
	return Decision{Allowed: true}
}

func (limiter *Limiter) rotateGenerationLocked(
	operation Operation,
	now time.Time,
) {
	start := limiter.generationStart[operation]
	if start.IsZero() {
		limiter.generationStart[operation] = now
		return
	}
	if now.Sub(start) < limiter.generationTTL[operation] {
		return
	}
	// Keep one grace generation. A bucket used during the next generation is
	// migrated into the current map in O(1); only an entire generation of
	// inactivity makes it eligible for this O(1) map replacement.
	limiter.previousBuckets[operation] = limiter.buckets[operation]
	limiter.previousOverflow[operation] = limiter.overflow[operation]
	limiter.buckets[operation] = make(map[string]*limiterBucket)
	limiter.overflow[operation] = nil
	limiter.generation[operation]++
	limiter.generationStart[operation] = now
	limiter.workUnits[operation]++
}

func (limiter *Limiter) subjectBucketLocked(
	operation Operation,
	subject string,
) *limiterBucket {
	if bucket := limiter.buckets[operation][subject]; bucket != nil {
		return bucket
	}
	bucket := limiter.previousBuckets[operation][subject]
	if bucket == nil {
		return nil
	}
	delete(limiter.previousBuckets[operation], subject)
	limiter.buckets[operation][subject] = bucket
	return bucket
}

func (limiter *Limiter) overflowBucketLocked(
	operation Operation,
) *limiterBucket {
	if bucket := limiter.overflow[operation]; bucket != nil {
		return bucket
	}
	bucket := limiter.previousOverflow[operation]
	if bucket == nil {
		return nil
	}
	limiter.previousOverflow[operation] = nil
	limiter.overflow[operation] = bucket
	return bucket
}

func (limiter *Limiter) subjectCountLocked(operation Operation) int {
	return len(limiter.buckets[operation]) +
		len(limiter.previousBuckets[operation])
}

func naturalRecoveryDuration(
	capacity float64,
	refillPerSecond float64,
) time.Duration {
	recoveryNanoseconds := capacity / refillPerSecond * float64(time.Second)
	if recoveryNanoseconds >= float64(math.MaxInt64) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(math.Ceil(recoveryNanoseconds))
}

func (limiter *Limiter) SubjectCount() int {
	if limiter == nil {
		return 0
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	count := 0
	for _, subjects := range limiter.buckets {
		count += len(subjects)
	}
	for _, subjects := range limiter.previousBuckets {
		count += len(subjects)
	}
	return count
}

func (limiter *Limiter) SubjectCountFor(operation Operation) int {
	if limiter == nil {
		return 0
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	return limiter.subjectCountLocked(operation)
}

func (limiter *Limiter) WorkUnitsFor(operation Operation) uint64 {
	if limiter == nil {
		return 0
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	return limiter.workUnits[operation]
}
