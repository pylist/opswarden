package agents

import (
	"math"
	"sync"
	"time"
)

type Operation string

const (
	OperationAuthFailure       Operation = "auth_failure"
	OperationBootstrap         Operation = "bootstrap"
	OperationLoginSource       Operation = "login_source"
	OperationReverifySource    Operation = "reverify_source"
	OperationReverifyPrincipal Operation = "reverify_principal"
	OperationRequestSource     Operation = "request_source"
	OperationRequestRead       Operation = "request_read"
	OperationRequestWrite      Operation = "request_write"
	OperationCredentialList    Operation = "credential_list"
	OperationCredentialRead    Operation = "credential_read"
	OperationCredentialWrite   Operation = "credential_write"
)

var allOperations = []Operation{
	OperationAuthFailure,
	OperationBootstrap,
	OperationLoginSource,
	OperationReverifySource,
	OperationReverifyPrincipal,
	OperationRequestSource,
	OperationRequestRead,
	OperationRequestWrite,
	OperationCredentialList,
	OperationCredentialRead,
	OperationCredentialWrite,
}

type LimiterConfig struct {
	Capacity        map[Operation]int
	RefillPerSecond map[Operation]float64
	MaxSubjects     int
	IdleTTL         time.Duration
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
	requests []LimitRequest
	resolved bool
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
	reservation.limiter.refundMany(reservation.requests, now)
}

type limiterBucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

type Limiter struct {
	mu          sync.Mutex
	capacity    map[Operation]float64
	refill      map[Operation]float64
	maxSubjects int
	idleTTL     time.Duration
	buckets     map[Operation]map[string]*limiterBucket
	lastNow     map[Operation]time.Time
}

func NewLimiter(config LimiterConfig) *Limiter {
	if config.MaxSubjects <= 0 {
		config.MaxSubjects = 10_000
	}
	if config.IdleTTL <= 0 {
		config.IdleTTL = 15 * time.Minute
	}
	limiter := &Limiter{
		capacity:    make(map[Operation]float64, len(allOperations)),
		refill:      make(map[Operation]float64, len(allOperations)),
		maxSubjects: config.MaxSubjects,
		idleTTL:     config.IdleTTL,
		buckets:     make(map[Operation]map[string]*limiterBucket),
		lastNow:     make(map[Operation]time.Time),
	}
	defaultCapacity := map[Operation]int{
		OperationAuthFailure: 5, OperationCredentialList: 60,
		OperationBootstrap:         2,
		OperationLoginSource:       20,
		OperationReverifySource:    10,
		OperationReverifyPrincipal: 5,
		OperationRequestSource:     200,
		OperationRequestRead:       120,
		OperationRequestWrite:      60,
		OperationCredentialRead:    30, OperationCredentialWrite: 20,
	}
	defaultRefill := map[Operation]float64{
		OperationAuthFailure: 1.0 / 60, OperationCredentialList: 1,
		OperationBootstrap:         1.0 / 60,
		OperationLoginSource:       1.0 / 6,
		OperationReverifySource:    1.0 / 30,
		OperationReverifyPrincipal: 1.0 / 60,
		OperationRequestSource:     10,
		OperationRequestRead:       2,
		OperationRequestWrite:      1,
		OperationCredentialRead:    0.5, OperationCredentialWrite: 1.0 / 3,
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
		limiter.buckets[operation] = make(map[string]*limiterBucket)
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

	type stagedBucket struct {
		request LimitRequest
		bucket  *limiterBucket
		tokens  float64
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	for _, request := range unique {
		if last := limiter.lastNow[request.Operation]; !last.IsZero() &&
			now.Before(last) {
			return nil, Decision{RetryAfter: last.Sub(now)}
		}
	}
	staged := make([]stagedBucket, 0, len(unique))
	var retryAfter time.Duration
	for _, request := range unique {
		capacity := limiter.capacity[request.Operation]
		bucket := limiter.buckets[request.Operation][request.Subject]
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
		if tokens < 1 {
			missing := 1 - tokens
			wait := time.Duration(math.Ceil(
				missing / limiter.refill[request.Operation] * float64(time.Second),
			))
			if wait > retryAfter {
				retryAfter = wait
			}
		}
		staged = append(staged, stagedBucket{
			request: request, bucket: bucket, tokens: tokens,
		})
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
			limiter.removeIdleLocked(item.request.Operation, now)
			if len(limiter.buckets[item.request.Operation]) >= limiter.maxSubjects {
				limiter.evictOldestLocked(item.request.Operation)
			}
			item.bucket = &limiterBucket{}
			limiter.buckets[item.request.Operation][item.request.Subject] = item.bucket
		}
		item.bucket.tokens = item.tokens - 1
		item.bucket.last = now
		item.bucket.lastSeen = now
	}
	return &Reservation{
		limiter: limiter, requests: unique,
	}, Decision{Allowed: true}
}

// Refund returns one previously reserved token. It is used when a request was
// admitted pessimistically but did not end in the failure being limited.
func (limiter *Limiter) Refund(
	subject string,
	operation Operation,
	now time.Time,
) {
	limiter.refundMany([]LimitRequest{{
		Subject: subject, Operation: operation,
	}}, now)
}

func (limiter *Limiter) refundMany(
	requests []LimitRequest,
	now time.Time,
) {
	if limiter == nil || len(requests) == 0 || now.IsZero() {
		return
	}
	now = now.UTC()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	for _, request := range requests {
		capacity, known := limiter.capacity[request.Operation]
		if !known || request.Subject == "" {
			continue
		}
		bucket := limiter.buckets[request.Operation][request.Subject]
		if bucket == nil {
			continue
		}
		if !now.Before(bucket.last) {
			elapsed := now.Sub(bucket.last).Seconds()
			bucket.tokens = math.Min(
				capacity,
				bucket.tokens+elapsed*limiter.refill[request.Operation],
			)
			bucket.last = now
			bucket.lastSeen = now
		}
		bucket.tokens = math.Min(capacity, bucket.tokens+1)
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
	limiter.lastNow[operation] = now
	subjects := limiter.buckets[operation]
	bucket, exists := subjects[subject]
	if !exists {
		if !consume {
			return Decision{Allowed: true}
		}
		limiter.removeIdleLocked(operation, now)
		if len(subjects) >= limiter.maxSubjects {
			limiter.evictOldestLocked(operation)
		}
		bucket = &limiterBucket{tokens: capacity, last: now, lastSeen: now}
		subjects[subject] = bucket
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
	return count
}

func (limiter *Limiter) SubjectCountFor(operation Operation) int {
	if limiter == nil {
		return 0
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	return len(limiter.buckets[operation])
}

func (limiter *Limiter) removeIdleLocked(operation Operation, now time.Time) {
	for subject, bucket := range limiter.buckets[operation] {
		if bucket.lastSeen.IsZero() ||
			now.Sub(bucket.lastSeen) >= limiter.idleTTL {
			delete(limiter.buckets[operation], subject)
		}
	}
}

func (limiter *Limiter) evictOldestLocked(operation Operation) {
	var oldestSubject string
	var oldest time.Time
	for subject, bucket := range limiter.buckets[operation] {
		if oldestSubject == "" || bucket.lastSeen.Before(oldest) ||
			(bucket.lastSeen.Equal(oldest) && subject < oldestSubject) {
			oldestSubject = subject
			oldest = bucket.lastSeen
		}
	}
	if oldestSubject != "" {
		delete(limiter.buckets[operation], oldestSubject)
	}
}
