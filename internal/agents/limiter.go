package agents

import (
	"math"
	"sync"
	"time"
)

type Operation string

const (
	OperationAuthFailure     Operation = "auth_failure"
	OperationCredentialList  Operation = "credential_list"
	OperationCredentialRead  Operation = "credential_read"
	OperationCredentialWrite Operation = "credential_write"
)

var allOperations = []Operation{
	OperationAuthFailure,
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
		OperationCredentialRead: 30, OperationCredentialWrite: 20,
	}
	defaultRefill := map[Operation]float64{
		OperationAuthFailure: 1.0 / 60, OperationCredentialList: 1,
		OperationCredentialRead: 0.5, OperationCredentialWrite: 1.0 / 3,
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

// Refund returns one previously reserved token. It is used when a request was
// admitted pessimistically but did not end in the failure being limited.
func (limiter *Limiter) Refund(
	subject string,
	operation Operation,
	now time.Time,
) {
	if limiter == nil || subject == "" || now.IsZero() {
		return
	}
	capacity, known := limiter.capacity[operation]
	if !known {
		return
	}
	now = now.UTC()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	bucket := limiter.buckets[operation][subject]
	if bucket == nil {
		return
	}
	if !now.Before(bucket.last) {
		elapsed := now.Sub(bucket.last).Seconds()
		bucket.tokens = math.Min(
			capacity, bucket.tokens+elapsed*limiter.refill[operation],
		)
		bucket.last = now
		bucket.lastSeen = now
	}
	bucket.tokens = math.Min(capacity, bucket.tokens+1)
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
