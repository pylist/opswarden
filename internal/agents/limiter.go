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
	subjects    map[string]map[Operation]*limiterBucket
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
		subjects:    make(map[string]map[Operation]*limiterBucket),
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
		if refill <= 0 {
			refill = defaultRefill[operation]
		}
		limiter.capacity[operation] = float64(capacity)
		limiter.refill[operation] = refill
	}
	return limiter
}

func (limiter *Limiter) Allow(
	subject string,
	operation Operation,
	now time.Time,
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

	operations, exists := limiter.subjects[subject]
	if !exists {
		limiter.removeIdleLocked(now)
		if len(limiter.subjects) >= limiter.maxSubjects {
			return Decision{RetryAfter: limiter.idleTTL}
		}
		operations = make(map[Operation]*limiterBucket)
		limiter.subjects[subject] = operations
	}
	bucket, exists := operations[operation]
	if !exists {
		bucket = &limiterBucket{tokens: capacity, last: now, lastSeen: now}
		operations[operation] = bucket
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
	bucket.tokens--
	return Decision{Allowed: true}
}

func (limiter *Limiter) SubjectCount() int {
	if limiter == nil {
		return 0
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	return len(limiter.subjects)
}

func (limiter *Limiter) removeIdleLocked(now time.Time) {
	for subject, operations := range limiter.subjects {
		latest := time.Time{}
		for _, bucket := range operations {
			if bucket.lastSeen.After(latest) {
				latest = bucket.lastSeen
			}
		}
		if latest.IsZero() || now.Sub(latest) >= limiter.idleTTL {
			delete(limiter.subjects, subject)
		}
	}
}
