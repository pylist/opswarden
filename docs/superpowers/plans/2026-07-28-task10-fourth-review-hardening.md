# Task 10 Fourth Review Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make subject admission and protected JWT admission bounded O(1) while preserving stable per-session quotas and all prior authentication protections.

**Architecture:** Replace scan-and-evict limiter subject storage with fixed-cap maps and one fixed overflow bucket per operation; an unknown subject at capacity is charged only to overflow and cannot evict an established subject. Split pre-auth admission into source-first, token-format-specific stages: invalid human JWTs stop after the source quota and signature validation, valid JWTs use signed `sid + sub + route` identity, and Agent tokens use a full SHA-256 token fingerprint.

**Tech Stack:** Go 1.24, `net/http`, existing JWT signer, in-memory `agents.Limiter`, SQLite-backed identity/Agent services.

## Global Constraints

- Every limiter request performs a fixed amount of map work independent of subject count.
- Per-operation subject memory never exceeds the configured capacity plus one fixed overflow bucket.
- Unknown subjects at capacity cannot evict or reset established subject allowances.
- JWT validation before the strict pre-auth quota performs no database or audit write.
- Formal session/Agent authentication still runs after quota admission.

---

### Task 1: Fixed-cap O(1) limiter storage

**Files:**
- Modify: `internal/agents/limiter.go`
- Modify: `internal/agents/limiter_test.go`

- [ ] Add deterministic failing tests that fill 10,000 subjects, rotate 20,000 more, and assert a strict constant work counter, fixed memory, shared overflow allowance, retained established entries, and concurrent safety.
- [ ] Run `go test ./internal/agents -run 'TestLimiterFixedWork' -count=1` and observe failure from missing work metrics and eviction semantics.
- [ ] Remove idle-map and oldest-subject scans. Add one per-operation overflow bucket used whenever an unknown subject arrives at capacity; existing map entries continue to use direct lookup.
- [ ] Preserve atomic multi-bucket reservation, operation isolation, refund, time rollback, and race safety; re-run all Agent limiter tests.

### Task 2: Source-first and stable-session pre-auth flow

**Files:**
- Modify: `internal/httpapi/middleware.go`
- Modify: `internal/httpapi/router_test.go`

- [ ] Add failing tests proving 20,000 invalid JWTs create no strict token subjects and have bounded work, refreshed JWTs for one `sid + sub` share quota across source changes, other sessions remain isolated, and over-limit attempts cause zero session-idle/audit writes.
- [ ] Run the focused HTTP tests and observe invalid JWT token fingerprints populate strict limiter state and refreshed JWT strings receive independent allowance.
- [ ] Charge the trusted-source quota first. For Agent-shaped tokens, then charge a SHA-256 token-fingerprint quota. For human JWTs, strictly verify signature/claims without database access, derive a stable full SHA-256 `sid + sub + route` key, then charge the route quota.
- [ ] Reuse verified claims in authentication middleware through request context, retain formal `ResolveSession`, and keep reverify failure reservations distinct from request admission.

### Task 3: Report cleanup and verification

**Files:**
- Modify: `.superpowers/sdd/task-10-report.md`

- [ ] Rewrite Delivered so it describes only fixed-overflow limiter storage, dual login/reverify quotas, and final source-first stable-session pre-auth behavior; remove older eviction and combined-key descriptions.
- [ ] Run focused tests, `go test ./... -count=1`, `go test -race ./... -count=1`, `go vet ./...`, and `git diff --check`.
- [ ] Commit the fourth-review changes independently on top of `aa54e3b`, confirm a clean tracked worktree, and preserve the branch/worktree for the parent reviewer.
