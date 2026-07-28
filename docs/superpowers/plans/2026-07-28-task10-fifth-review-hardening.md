# Task 10 Fifth Review Hardening Plan

> **For Codex:** Execute this plan with the `executing-plans` skill, using TDD and verification-before-completion.

**Goal:** Prevent invalid Agent bearer tokens from consuming established-principal limiter state, isolate limiter overflow by authentication kind and route class, and add bounded O(1) limiter lifecycle reclamation.

**Architecture:** Add a read-only Agent authentication inspection step before strict rate limiting, while retaining the existing writer-backed authentication as the authoritative fresh check. Split limiter operations into low-cardinality human/agent route namespaces. Reclaim limiter state by atomically swapping per-operation generations after a recovery-safe TTL, with generation-aware refunds.

**Tech Stack:** Go, SQLite, `net/http`, existing OpsWarden service and repository layers.

---

### Task 1: Add read-only Agent credential inspection

**Files:**
- Modify: `internal/agents/model.go`
- Modify: `internal/agents/service.go`
- Modify: `internal/agents/service_test.go`

**Steps:**
1. Add failing tests proving inspection validates token, agent, and grants without updating `last_used_at` or writing success audit data.
2. Add a race-oriented test proving a token revoked after inspection is rejected by the authoritative writer-backed `Authenticate` call.
3. Implement `InspectAuthentication` using the reader connection, existing constant-time candidate validation, and read-only grant lookup.
4. Run focused Agent service tests.

### Task 2: Gate strict Agent quotas behind successful inspection

**Files:**
- Modify: `internal/httpapi/router.go`
- Modify: `internal/httpapi/middleware.go`
- Modify: `internal/httpapi/middleware_test.go`
- Modify: affected HTTP test fakes

**Steps:**
1. Add failing tests for 10,000/20,000 syntactically Agent-shaped invalid tokens: no strict limiter subjects, no established overflow consumption, no writer authentication, no success audit or `last_used_at` mutation, and bounded work.
2. Add a valid-token test proving inspection precedes strict limiting and authoritative authentication remains bounded.
3. Store only stable inspected Agent/token identity for limiter subject construction; do not treat inspection as formal authentication.
4. Route inspection failures through the anonymous authentication-failure gate.
5. Keep writer-backed `Authenticate` as the final fresh authorization check.
6. Run focused HTTP middleware tests.

### Task 3: Isolate limiter namespaces by principal kind and route class

**Files:**
- Modify: `internal/agents/limiter.go`
- Modify: `internal/agents/limiter_test.go`
- Modify: `internal/httpapi/middleware.go`
- Modify: affected HTTP tests

**Steps:**
1. Add failing tests proving human read, human write, Agent read, Agent write, and credential route overflow cannot affect one another.
2. Introduce distinct low-cardinality operations for human/Agent source and strict route classes.
3. Update default capacities and HTTP mappings.
4. Run limiter and HTTP tests.

### Task 4: Add O(1) generation lifecycle reclamation

**Files:**
- Modify: `internal/agents/limiter.go`
- Modify: `internal/agents/limiter_test.go`

**Steps:**
1. Add failing tests for no early reset, recovery-safe TTL clamping, O(1) generation swap, bounded memory/work, rollback fail-closed behavior, and stale reservation refunds.
2. Replace unused `IdleTTL` with `GenerationTTL`.
3. Maintain a per-operation generation start, generation number, subject map, and overflow bucket.
4. Swap the operation generation in O(1) after a TTL no shorter than that operation's natural full-recovery time.
5. Make refunds generation-aware so stale receipts cannot affect a new generation.
6. Remove public subject-based `Limiter.Refund` and migrate/delete its tests and callers.
7. Run focused limiter tests including race detection.

### Task 5: Verify and commit

**Steps:**
1. Run `gofmt` on changed Go files.
2. Run focused package tests.
3. Run the full test suite.
4. Run the full race suite.
5. Run `go vet ./...`.
6. Inspect `git diff --check`, status, and final diff.
7. Commit the fifth-review hardening as an independent commit and report the commit hash and verification evidence.
