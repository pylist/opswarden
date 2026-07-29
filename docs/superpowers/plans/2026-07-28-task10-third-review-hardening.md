# Task 10 Third Review Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound every authentication-related CPU and durable-write path before expensive or persistent work, without weakening session, Agent, audit, or bootstrap checks.

**Architecture:** Add an atomic multi-bucket reservation primitive to the existing in-memory limiter, then use it for login, reverify, and pre-auth request quotas. Replace the per-key anonymous failure cache with per-operation fixed-budget windows and a non-evicting overflow bucket. Keep formal JWT/session and Agent authentication unchanged after the pre-auth gate so revocation and authorization remain fresh.

**Tech Stack:** Go 1.25.12, `net/http`, SQLite, existing `agents.Limiter`, identity and audit services.

## Global Constraints

- All failure and request quota state is bounded in memory and concurrency-safe.
- No submitted password, TOTP, JWT, Agent token, query, or raw identifier is logged or durably audited.
- Authentication and bootstrap fail closed when `AuthAudit` is unavailable.
- Production service interfaces retain fresh transactional session, revocation, TOTP replay, bootstrap uniqueness, and audit checks.

---

### Task 1: Atomic multi-bucket reservations

**Files:**
- Modify: `internal/agents/limiter.go`
- Modify: `internal/agents/limiter_test.go`

**Interfaces:**
- Produces: `LimitRequest`, `Limiter.Reserve`, and `Reservation.Commit`/`Reservation.Refund`.
- Consumes: existing per-operation capacity, refill, rollback-clock, and subject-bound behavior.

- [ ] Write tests proving two buckets are consumed atomically, denial consumes neither bucket, refund restores both, and concurrent reservations cannot exceed either capacity.
- [ ] Run `go test ./internal/agents -run 'TestLimiterAtomic' -count=1` and observe failure because the reservation API is missing.
- [ ] Implement a single-lock staged reservation that deduplicates requests, checks all buckets before consuming any token, and refunds exactly once.
- [ ] Re-run the focused limiter tests and keep all existing limiter tests green.

### Task 2: O(1) bounded authentication-failure audit gate

**Files:**
- Modify: `internal/httpapi/auth_failure_gate.go`
- Modify: `internal/httpapi/auth_failure_gate_test.go`
- Modify: `internal/httpapi/router.go`

**Interfaces:**
- Produces: per-operation `observe` and `suppress` decisions with a fixed durable-row budget, fixed key capacity, overflow suppression, and rollover aggregate.
- Consumes: `AuthenticationAuditRecorder.RecordReadBeforeReturn`.

- [ ] Write tests with more than 4096 rotating sources proving no key eviction resets individual-write allowance; add multi-operation isolation, rollover, aggregate-row budget, and constant-work counter assertions.
- [ ] Run the focused gate tests and observe row counts exceed the required bounds with the current eviction implementation.
- [ ] Replace oldest-key scans with per-operation state whose key map is replaced in O(1) at rollover. Unknown keys after capacity enter a fixed overflow counter and never receive individual-write allowance.
- [ ] Route anonymous and rate-limited known failures through one aggregate writer and verify no duplicate audit paths remain.

### Task 3: Dual login and reverify failure quotas

**Files:**
- Modify: `internal/httpapi/auth_handlers.go`
- Modify: `internal/httpapi/middleware.go`
- Modify: `internal/httpapi/router_test.go`
- Modify: `internal/agents/limiter.go`

**Interfaces:**
- Consumes: atomic limiter reservations and bounded failure aggregate writer.
- Produces: login source-total plus account/challenge reservations; reverify source plus signed session/user reservations.

- [ ] Write failing tests for rotating login emails from one IP, one account from rotating IPs, NAT users below the wider source allowance, and concurrent reservation atomicity.
- [ ] Write failing tests proving a stolen JWT cannot enumerate TOTP codes, IP rotation cannot evade the session/user bucket, other sessions/users remain isolated, and successful reverify refunds both buckets.
- [ ] Reserve login buckets only after strict body decoding and before password/TOTP work. Commit genuine authentication failures; refund success, malformed input, KDF saturation, and non-authentication errors.
- [ ] In pre-auth middleware, verify the JWT signature without database access and reserve reverify buckets before session resolution. Carry the reservation in request context and apply the same commit/refund rules in the handler.
- [ ] On quota denial, skip TOTP and individual audit, add only a bounded aggregate observation, and return 429.

### Task 4: Pre-auth protected-route request quotas

**Files:**
- Modify: `internal/httpapi/middleware.go`
- Modify: `internal/httpapi/router.go`
- Modify: `internal/httpapi/router_test.go`
- Modify: `internal/agents/limiter.go`

**Interfaces:**
- Produces: route classification for generic read/write and credential list/read/write.
- Consumes: SHA-256 bearer fingerprints and trusted request source metadata.

- [ ] Write failing tests showing valid low-privilege token floods currently cause unbounded `ResolveSession`/`Authenticate` and success-audit calls, including `/me`, assets, and credentials.
- [ ] Add assertions that over-limit calls leave idle/last-used/audit counters unchanged and that another token, another source, and the other human/Agent namespace remain usable.
- [ ] Before formal authentication, atomically consume a wider source-total bucket and stricter bearer-fingerprint route bucket. Never store or log the bearer or fingerprint.
- [ ] Remove the post-auth credential limiter so each request is charged exactly once; keep formal authentication and authorization checks after admission.

### Task 5: Fail-closed dependencies and non-leaking bootstrap

**Files:**
- Modify: `internal/httpapi/router.go`
- Modify: `internal/httpapi/middleware.go`
- Modify: `internal/httpapi/auth_handlers.go`
- Modify: `internal/httpapi/router_test.go`
- Modify: `internal/identity/service.go`

**Interfaces:**
- Produces: `IdentityService.InitialOwnerSourceAllowed(netip.Addr) bool`.
- Consumes: configured internal bootstrap CIDRs and `AuthAudit`.

- [ ] Write failing tests proving nil `AuthAudit` currently permits login/bootstrap or reaches persistent authentication, and that an external bootstrap source currently invokes `HasInitialOwner`.
- [ ] Add an API dependency guard before rate limiting/authentication that returns 503 without calling domain services whenever `AuthAudit` is nil.
- [ ] Expose the identity service’s read-only source-policy check and call it at the beginning of bootstrap handling, before body decoding and `HasInitialOwner`; return a uniform 403 externally.
- [ ] Keep the domain transaction’s source-policy and unique-owner checks unchanged and run focused HTTP and identity tests.

### Task 6: Verification, report, and independent commit

**Files:**
- Modify: `.superpowers/sdd/task-10-report.md` (ignored shared-workspace report)

**Interfaces:**
- Consumes: all preceding regression suites.
- Produces: one independent hardening commit based on `20f8c37`.

- [ ] Run focused RED/GREEN suites for limiter, failure gate, login, reverify, pre-auth requests, nil audit, and bootstrap source ordering.
- [ ] Run `gofmt`, `go test ./... -count=1`, `go test -race ./... -count=1`, `go vet ./...`, and `git diff --check`.
- [ ] Update the Task 10 report with exact behavior and verification evidence.
- [ ] Commit the reviewed files with a focused security-hardening message and confirm the tracked worktree is clean.
