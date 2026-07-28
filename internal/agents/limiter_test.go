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

func subjectForTest(index int) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	return "subject-" + string(digits[index%len(digits)])
}
