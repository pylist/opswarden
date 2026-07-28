package agents

import (
	"sync"
	"testing"
	"time"
)

func TestLimiterSeparatesSubjectsAndOperations(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{
			OperationCredentialRead: 1,
			OperationCredentialList: 1,
		},
		RefillPerSecond: map[Operation]float64{
			OperationCredentialRead: 1,
			OperationCredentialList: 1,
		},
		MaxSubjects: 16,
	})
	if !limiter.Allow("agent-a", OperationCredentialRead, now).Allowed {
		t.Fatal("first request denied")
	}
	if limiter.Allow("agent-a", OperationCredentialRead, now).Allowed {
		t.Fatal("exhausted bucket allowed")
	}
	if !limiter.Allow("agent-b", OperationCredentialRead, now).Allowed {
		t.Fatal("one agent blocked another")
	}
	if !limiter.Allow("agent-a", OperationCredentialList, now).Allowed {
		t.Fatal("read bucket blocked list bucket")
	}
	if !limiter.Allow("human:session-a", OperationCredentialRead, now).Allowed {
		t.Fatal("agent blocked human")
	}
}

func TestLimiterReservationPreventsConcurrentBurstAndCanBeRefunded(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{OperationAuthFailure: 1},
		RefillPerSecond: map[Operation]float64{
			OperationAuthFailure: 0.000001,
		},
	})
	if !limiter.Allow("login-ip", OperationAuthFailure, now).Allowed {
		t.Fatal("initial reservation denied")
	}
	const attempts = 64
	results := make(chan bool, attempts)
	var workers sync.WaitGroup
	for range attempts {
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- limiter.Allow(
				"login-ip", OperationAuthFailure, now,
			).Allowed
		}()
	}
	workers.Wait()
	close(results)
	for allowed := range results {
		if allowed {
			t.Fatal("concurrent burst escaped the outstanding reservation")
		}
	}
	limiter.Refund("login-ip", OperationAuthFailure, now)
	if !limiter.Allow("login-ip", OperationAuthFailure, now).Allowed {
		t.Fatal("refunded non-failure did not restore capacity")
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
			OperationAuthFailure:    1,
			OperationCredentialRead: 1,
		},
		RefillPerSecond: map[Operation]float64{
			OperationAuthFailure:    1,
			OperationCredentialRead: 1,
		},
		MaxSubjects: 1,
	})
	if !limiter.Allow("attacker-ip", OperationAuthFailure, now).Allowed {
		t.Fatal("auth failure bucket denied first subject")
	}
	if !limiter.Allow(
		"human:session", OperationCredentialRead, now,
	).Allowed {
		t.Fatal("auth-failure subject cap blocked credential read")
	}
}

func TestLimiterFullOperationEvictsOldestForNewLegitimateSubject(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter(LimiterConfig{
		Capacity: map[Operation]int{OperationAuthFailure: 1},
		RefillPerSecond: map[Operation]float64{
			OperationAuthFailure: 1,
		},
		MaxSubjects: 2,
		IdleTTL:     time.Hour,
	})
	if !limiter.Allow("attacker-a", OperationAuthFailure, now).Allowed ||
		!limiter.Allow(
			"attacker-b", OperationAuthFailure, now.Add(time.Second),
		).Allowed {
		t.Fatal("attack subjects did not enter")
	}
	if !limiter.Allow(
		"legitimate", OperationAuthFailure, now.Add(2*time.Second),
	).Allowed {
		t.Fatal("full bucket map permanently locked out new subject")
	}
	if limiter.SubjectCountFor(OperationAuthFailure) != 2 {
		t.Fatalf(
			"auth subjects=%d",
			limiter.SubjectCountFor(OperationAuthFailure),
		)
	}
}

func subjectForTest(index int) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	return "subject-" + string(digits[index%len(digits)])
}
