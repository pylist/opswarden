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
	items    []reservationItem
	resolved bool
}

type reservationItem struct {
	subject   string
	operation Operation
	overflow  bool
	units     float64
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
	mu          sync.Mutex
	capacity    map[Operation]float64
	refill      map[Operation]float64
	maxSubjects int
	buckets     map[Operation]map[string]*limiterBucket
	overflow    map[Operation]*limiterBucket
	lastNow     map[Operation]time.Time
	workUnits   map[Operation]uint64
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
		buckets:     make(map[Operation]map[string]*limiterBucket),
		overflow:    make(map[Operation]*limiterBucket),
		lastNow:     make(map[Operation]time.Time),
		workUnits:   make(map[Operation]uint64),
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
	for _, request := range unique {
		if last := limiter.lastNow[request.Operation]; !last.IsZero() &&
			now.Before(last) {
			return nil, Decision{RetryAfter: last.Sub(now)}
		}
	}
	staged := make([]stagedBucket, 0, len(unique))
	stagedIndexes := make(map[stagedKey]int, len(unique))
	pendingNew := make(map[Operation]int, len(unique))
	var retryAfter time.Duration
	for _, request := range unique {
		capacity := limiter.capacity[request.Operation]
		bucket := limiter.buckets[request.Operation][request.Subject]
		limiter.workUnits[request.Operation]++
		key := stagedKey{
			operation: request.Operation,
			subject:   request.Subject,
		}
		create := false
		if bucket == nil {
			if len(limiter.buckets[request.Operation])+
				pendingNew[request.Operation] < limiter.maxSubjects {
				pendingNew[request.Operation]++
				create = true
			} else {
				key.subject = ""
				key.overflow = true
				bucket = limiter.overflow[request.Operation]
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
		})
	}
	return &Reservation{
		limiter: limiter, items: reservationItems,
	}, Decision{Allowed: true}
}

// Refund returns one previously reserved token. It is used when a request was
// admitted pessimistically but did not end in the failure being limited.
func (limiter *Limiter) Refund(
	subject string,
	operation Operation,
	now time.Time,
) {
	limiter.refundMany([]reservationItem{{
		subject: subject, operation: operation, units: 1,
	}}, now)
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
			item.units <= 0 {
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
	limiter.workUnits[operation]++
	if !exists {
		if !consume {
			if len(subjects) < limiter.maxSubjects {
				return Decision{Allowed: true}
			}
			bucket = limiter.overflow[operation]
			if bucket == nil {
				return Decision{Allowed: true}
			}
		} else if len(subjects) >= limiter.maxSubjects {
			bucket = limiter.overflow[operation]
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

func (limiter *Limiter) WorkUnitsFor(operation Operation) uint64 {
	if limiter == nil {
		return 0
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	return limiter.workUnits[operation]
}
