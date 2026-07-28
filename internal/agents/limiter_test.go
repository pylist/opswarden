package agents

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestLimiterSeparatesSubjectsAndOperations(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{
			OperationAgentCredentialRead: 1,
			OperationAgentCredentialList: 1,
		},
		RefillPerSecond: map[Operation]float64{
			OperationAgentCredentialRead: 1,
			OperationAgentCredentialList: 1,
		},
		MaxSubjects: 16,
	})
	if !limiter.Allow("agent-a", OperationAgentCredentialRead, now).Allowed {
		t.Fatal("first request denied")
	}
	if limiter.Allow("agent-a", OperationAgentCredentialRead, now).Allowed {
		t.Fatal("exhausted bucket allowed")
	}
	if !limiter.Allow("agent-b", OperationAgentCredentialRead, now).Allowed {
		t.Fatal("one agent blocked another")
	}
	if !limiter.Allow("agent-a", OperationAgentCredentialList, now).Allowed {
		t.Fatal("read bucket blocked list bucket")
	}
	if !limiter.Allow("human:session-a", OperationAgentCredentialRead, now).Allowed {
		t.Fatal("agent blocked human")
	}
}

func TestLimiterAtomicReservationConsumesAndRefundsEveryBucket(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{
			OperationAuthFailure: 1,
			OperationBootstrap:   1,
		},
		RefillPerSecond: map[Operation]float64{
			OperationAuthFailure: 0.000001,
			OperationBootstrap:   0.000001,
		},
	})
	requests := []LimitRequest{
		{Subject: "source", Operation: OperationBootstrap},
		{Subject: "account", Operation: OperationAuthFailure},
	}
	reservation, decision := limiter.Reserve(requests, now)
	if !decision.Allowed || reservation == nil {
		t.Fatalf("initial reservation=%v decision=%+v", reservation, decision)
	}
	if _, second := limiter.Reserve(requests, now); second.Allowed {
		t.Fatal("exhausted atomic reservation was allowed")
	}
	reservation.Refund(now)
	if _, refunded := limiter.Reserve(requests, now); !refunded.Allowed {
		t.Fatalf("refund did not restore both buckets: %+v", refunded)
	}
}

func TestLimiterAtomicReservationDenialConsumesNoOtherBucket(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{
			OperationAuthFailure: 1,
			OperationBootstrap:   1,
		},
		RefillPerSecond: map[Operation]float64{
			OperationAuthFailure: 0.000001,
			OperationBootstrap:   0.000001,
		},
	})
	if !limiter.Allow("blocked", OperationAuthFailure, now).Allowed {
		t.Fatal("failed to exhaust strict bucket")
	}
	_, denied := limiter.Reserve([]LimitRequest{
		{Subject: "fresh-source", Operation: OperationBootstrap},
		{Subject: "blocked", Operation: OperationAuthFailure},
	}, now)
	if denied.Allowed {
		t.Fatal("reservation ignored exhausted strict bucket")
	}
	if !limiter.Allow("fresh-source", OperationBootstrap, now).Allowed {
		t.Fatal("denied reservation consumed the wider source bucket")
	}
}

func TestLimiterAtomicReservationIsConcurrent(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{
			OperationAuthFailure: 3,
			OperationBootstrap:   5,
		},
		RefillPerSecond: map[Operation]float64{
			OperationAuthFailure: 0.000001,
			OperationBootstrap:   0.000001,
		},
	})
	const attempts = 64
	results := make(chan bool, attempts)
	var workers sync.WaitGroup
	for range attempts {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, decision := limiter.Reserve([]LimitRequest{
				{Subject: "source", Operation: OperationBootstrap},
				{Subject: "account", Operation: OperationAuthFailure},
			}, now)
			results <- decision.Allowed
		}()
	}
	workers.Wait()
	close(results)
	allowed := 0
	for result := range results {
		if result {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("allowed=%d want strict capacity 3", allowed)
	}
}

func TestLimiterIsBoundedRaceSafeAndTimeRollbackFailsSafe(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{OperationAuthFailure: 2},
		RefillPerSecond: map[Operation]float64{
			OperationAuthFailure: 1,
		},
		MaxSubjects: 8,
	})
	if !limiter.Allow("stable", OperationAuthFailure, now).Allowed {
		t.Fatal("new stable subject denied")
	}
	var workers sync.WaitGroup
	for index := 0; index < 32; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			limiter.Allow(subjectForTest(index), OperationAuthFailure, now)
		}(index)
	}
	workers.Wait()
	if limiter.SubjectCount() > 8 {
		t.Fatalf("unbounded subjects: %d", limiter.SubjectCount())
	}

	rollback := limiter.Allow("stable", OperationAuthFailure, now.Add(-time.Second))
	if rollback.Allowed {
		t.Fatal("clock rollback replenished or allowed bucket")
	}
}

func TestLimiterSubjectCapacityIsPerOperation(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{
			OperationAuthFailure:         1,
			OperationHumanCredentialRead: 1,
		},
		RefillPerSecond: map[Operation]float64{
			OperationAuthFailure:         1,
			OperationHumanCredentialRead: 1,
		},
		MaxSubjects: 1,
	})
	if !limiter.Allow("attacker-ip", OperationAuthFailure, now).Allowed {
		t.Fatal("auth failure bucket denied first subject")
	}
	if !limiter.Allow(
		"human:session", OperationHumanCredentialRead, now,
	).Allowed {
		t.Fatal("auth-failure subject cap blocked credential read")
	}
}

func TestLimiterOverflowIsIsolatedByPrincipalKindAndRouteClass(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	sourceOperations := []Operation{
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
	}
	strictOperations := []Operation{
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
	operations := append(
		append([]Operation(nil), sourceOperations...),
		strictOperations...,
	)
	capacity := make(map[Operation]int, len(operations))
	refill := make(map[Operation]float64, len(operations))
	for _, operation := range operations {
		capacity[operation] = 1
		refill[operation] = 0.000001
	}
	limiter := NewLimiter(LimiterConfig{
		Capacity: capacity, RefillPerSecond: refill, MaxSubjects: 1,
	})
	exhaustOverflow := func(operation Operation) {
		t.Helper()
		if !limiter.Allow("established", operation, now).Allowed {
			t.Fatalf("%s established subject denied", operation)
		}
		if !limiter.Allow("overflow-a", operation, now).Allowed {
			t.Fatalf("%s overflow denied its first allowance", operation)
		}
		if limiter.Allow("overflow-b", operation, now).Allowed {
			t.Fatalf("%s overflow was not exhausted", operation)
		}
	}

	exhaustOverflow(OperationHumanRequestReadSource)
	for _, operation := range operations {
		if operation == OperationHumanRequestReadSource {
			continue
		}
		if !limiter.Check("source-isolated", operation, now).Allowed {
			t.Fatalf("human read source overflow affected %s", operation)
		}
	}
	exhaustOverflow(OperationHumanRequestRead)
	for _, operation := range strictOperations {
		if operation == OperationHumanRequestRead {
			continue
		}
		if !limiter.Check("route-isolated", operation, now).Allowed {
			t.Fatalf("human read overflow affected %s", operation)
		}
	}
}

func TestLimiterFixedOverflowDoesNotEvictEstablishedSubject(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{OperationAuthFailure: 2},
		RefillPerSecond: map[Operation]float64{
			OperationAuthFailure: 0.000001,
		},
		MaxSubjects:   2,
		GenerationTTL: time.Hour,
	})
	if !limiter.Allow("attacker-a", OperationAuthFailure, now).Allowed ||
		!limiter.Allow("attacker-a", OperationAuthFailure, now).Allowed ||
		!limiter.Allow("attacker-b", OperationAuthFailure, now).Allowed {
		t.Fatal("established subjects did not enter")
	}
	for _, unknown := range []string{"unknown-a", "unknown-b"} {
		if !limiter.Allow(unknown, OperationAuthFailure, now).Allowed {
			t.Fatalf("overflow allowance denied %s too early", unknown)
		}
	}
	if limiter.Allow("unknown-c", OperationAuthFailure, now).Allowed {
		t.Fatal("unknown subjects received independent fresh allowances")
	}
	if limiter.Allow("attacker-a", OperationAuthFailure, now).Allowed {
		t.Fatal("overflow evicted and reset an established subject")
	}
	if limiter.SubjectCountFor(OperationAuthFailure) != 2 {
		t.Fatalf(
			"auth subjects=%d",
			limiter.SubjectCountFor(OperationAuthFailure),
		)
	}
}

func TestLimiterGenerationDoesNotResetBeforeNaturalRecovery(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{OperationAgentRequestRead: 5},
		RefillPerSecond: map[Operation]float64{
			OperationAgentRequestRead: 1,
		},
		MaxSubjects:   1,
		GenerationTTL: time.Second,
	})
	for range 5 {
		if !limiter.Allow(
			"established", OperationAgentRequestRead, now,
		).Allowed {
			t.Fatal("failed to consume initial capacity")
		}
	}
	allowed := 0
	for range 3 {
		if limiter.Allow(
			"established", OperationAgentRequestRead, now.Add(2*time.Second),
		).Allowed {
			allowed++
		}
	}
	if allowed != 2 {
		t.Fatalf("generation reset before five-second recovery: allowed=%d", allowed)
	}
}

func TestLimiterGenerationSwapIsConstantWorkAndBounded(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	const subjectCap = 10_000
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{OperationAgentRequestRead: 1},
		RefillPerSecond: map[Operation]float64{
			OperationAgentRequestRead: 1,
		},
		MaxSubjects:   subjectCap,
		GenerationTTL: time.Second,
	})
	for index := range subjectCap {
		if !limiter.Allow(
			fmt.Sprintf("old-%d", index), OperationAgentRequestRead, now,
		).Allowed {
			t.Fatalf("old generation subject %d denied", index)
		}
	}
	if !limiter.Allow(
		"boundary-overflow", OperationAgentRequestRead, now.Add(time.Second),
	).Allowed {
		t.Fatal("boundary overflow subject denied")
	}
	before := limiter.WorkUnitsFor(OperationAgentRequestRead)
	if !limiter.Allow(
		"new-generation", OperationAgentRequestRead, now.Add(2*time.Second),
	).Allowed {
		t.Fatal("new generation subject denied")
	}
	if work := limiter.WorkUnitsFor(OperationAgentRequestRead) - before; work > 3 {
		t.Fatalf("generation swap work=%d want <=3", work)
	}
	if count := limiter.SubjectCountFor(OperationAgentRequestRead); count != 1 {
		t.Fatalf("new generation retained %d subjects", count)
	}
}

func TestLimiterStaleReservationCannotRefundNewGeneration(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{OperationAgentRequestRead: 1},
		RefillPerSecond: map[Operation]float64{
			OperationAgentRequestRead: 1,
		},
		MaxSubjects:   1,
		GenerationTTL: time.Second,
	})
	reservation, decision := limiter.Reserve([]LimitRequest{{
		Subject: "stable", Operation: OperationAgentRequestRead,
	}}, now)
	if !decision.Allowed || reservation == nil {
		t.Fatalf("old reservation denied: %+v", decision)
	}
	next := now.Add(time.Second)
	if !limiter.Allow("stable", OperationAgentRequestRead, next).Allowed {
		t.Fatal("new generation allowance denied")
	}
	reservation.Refund(next)
	if limiter.Allow("stable", OperationAgentRequestRead, next).Allowed {
		t.Fatal("stale reservation refunded the new generation")
	}
}

func TestLimiterStaleOverflowReservationCannotRefundNewGeneration(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{OperationAgentRequestRead: 1},
		RefillPerSecond: map[Operation]float64{
			OperationAgentRequestRead: 1,
		},
		MaxSubjects:   1,
		GenerationTTL: time.Second,
	})
	if !limiter.Allow("established", OperationAgentRequestRead, now).Allowed {
		t.Fatal("old direct subject denied")
	}
	reservation, decision := limiter.Reserve([]LimitRequest{{
		Subject: "old-overflow", Operation: OperationAgentRequestRead,
	}}, now)
	if !decision.Allowed || reservation == nil {
		t.Fatalf("old overflow reservation denied: %+v", decision)
	}
	firstBoundary := now.Add(time.Second)
	if !limiter.Allow(
		"established", OperationAgentRequestRead, firstBoundary,
	).Allowed {
		t.Fatal("active direct subject did not survive first boundary")
	}
	next := now.Add(2 * time.Second)
	if !limiter.Allow("new-overflow", OperationAgentRequestRead, next).Allowed {
		t.Fatal("new overflow subject denied")
	}
	reservation.Refund(next)
	if limiter.Allow(
		"another-overflow", OperationAgentRequestRead, next,
	).Allowed {
		t.Fatal("stale receipt refunded the new overflow bucket")
	}
}

func TestLimiterRollbackCannotTriggerGenerationReset(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{OperationAgentRequestRead: 1},
		RefillPerSecond: map[Operation]float64{
			OperationAgentRequestRead: 1,
		},
		GenerationTTL: time.Second,
	})
	if !limiter.Allow(
		"stable", OperationAgentRequestRead, now.Add(time.Second),
	).Allowed {
		t.Fatal("forward request denied")
	}
	if limiter.Allow("stable", OperationAgentRequestRead, now).Allowed {
		t.Fatal("clock rollback reset or replenished the generation")
	}
}

func TestLimiterRefundAdvancesOperationClockForRollbackSafety(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{OperationAgentRequestRead: 1},
		RefillPerSecond: map[Operation]float64{
			OperationAgentRequestRead: 1,
		},
		GenerationTTL: time.Hour,
	})
	reservation, decision := limiter.Reserve([]LimitRequest{{
		Subject: "reserved", Operation: OperationAgentRequestRead,
	}}, now)
	if !decision.Allowed || reservation == nil {
		t.Fatalf("reservation denied: %+v", decision)
	}
	reservation.Refund(now.Add(10 * time.Second))
	if limiter.Allow(
		"different-subject", OperationAgentRequestRead,
		now.Add(5*time.Second),
	).Allowed {
		t.Fatal("refund time allowed a cross-subject clock rollback")
	}
}

func TestLimiterGenerationPreservesSubjectUsedNearBoundary(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{OperationAgentRequestRead: 5},
		RefillPerSecond: map[Operation]float64{
			OperationAgentRequestRead: 1,
		},
		MaxSubjects:   2,
		GenerationTTL: 5 * time.Second,
	})
	if !limiter.Allow("starter", OperationAgentRequestRead, now).Allowed {
		t.Fatal("failed to start generation")
	}
	nearBoundary := now.Add(4900 * time.Millisecond)
	for range 5 {
		if !limiter.Allow(
			"active", OperationAgentRequestRead, nearBoundary,
		).Allowed {
			t.Fatal("failed to consume near-boundary capacity")
		}
	}
	if limiter.Allow(
		"active", OperationAgentRequestRead, now.Add(5*time.Second),
	).Allowed {
		t.Fatal("generation boundary reset a recently consumed subject")
	}
}

func TestLimiterFixedWorkWithTenThousandEstablishedAndRotatingSubjects(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	const subjectCap = 10_000
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{OperationAgentRequestRead: 1},
		RefillPerSecond: map[Operation]float64{
			OperationAgentRequestRead: 0.000001,
		},
		MaxSubjects: subjectCap,
	})
	for index := range subjectCap {
		if !limiter.Allow(
			fmt.Sprintf("established-%d", index),
			OperationAgentRequestRead, now,
		).Allowed {
			t.Fatalf("established subject %d denied", index)
		}
	}
	before := limiter.WorkUnitsFor(OperationAgentRequestRead)
	started := time.Now()
	for index := range 20_000 {
		limiter.Allow(
			fmt.Sprintf("rotating-%d", index),
			OperationAgentRequestRead, now,
		)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("rotating subjects took %s; request path is not bounded", elapsed)
	}
	work := limiter.WorkUnitsFor(OperationAgentRequestRead) - before
	if work > 20_000*2 {
		t.Fatalf("work units=%d want <=%d", work, 20_000*2)
	}
	if count := limiter.SubjectCountFor(OperationAgentRequestRead); count != subjectCap {
		t.Fatalf("subject count=%d want fixed cap %d", count, subjectCap)
	}
}

func TestLimiterExistingSubjectRemainsConstantWorkAfterOverflow(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{OperationAgentRequestRead: 2},
		RefillPerSecond: map[Operation]float64{
			OperationAgentRequestRead: 0.000001,
		},
		MaxSubjects: 1,
	})
	if !limiter.Allow("established", OperationAgentRequestRead, now).Allowed {
		t.Fatal("established subject denied")
	}
	for index := range 1000 {
		limiter.Allow(
			fmt.Sprintf("overflow-%d", index), OperationAgentRequestRead, now,
		)
	}
	before := limiter.WorkUnitsFor(OperationAgentRequestRead)
	if !limiter.Allow("established", OperationAgentRequestRead, now).Allowed {
		t.Fatal("established subject lost its remaining allowance")
	}
	if work := limiter.WorkUnitsFor(OperationAgentRequestRead) - before; work > 2 {
		t.Fatalf("established lookup work=%d", work)
	}
}

func TestLimiterOverflowAllowanceIsSharedConcurrently(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{OperationAgentRequestRead: 4},
		RefillPerSecond: map[Operation]float64{
			OperationAgentRequestRead: 0.000001,
		},
		MaxSubjects: 1,
	})
	if !limiter.Allow("established", OperationAgentRequestRead, now).Allowed {
		t.Fatal("established subject denied")
	}
	const attempts = 64
	results := make(chan bool, attempts)
	var workers sync.WaitGroup
	for index := range attempts {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			results <- limiter.Allow(
				fmt.Sprintf("rotating-%d", index),
				OperationAgentRequestRead, now,
			).Allowed
		}(index)
	}
	workers.Wait()
	close(results)
	allowed := 0
	for result := range results {
		if result {
			allowed++
		}
	}
	if allowed != 4 {
		t.Fatalf("overflow allowed=%d want one shared capacity of 4", allowed)
	}
	if count := limiter.SubjectCountFor(OperationAgentRequestRead); count != 1 {
		t.Fatalf("subject count=%d want fixed map size 1", count)
	}
}

func subjectForTest(index int) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	return "subject-" + string(digits[index%len(digits)])
}
