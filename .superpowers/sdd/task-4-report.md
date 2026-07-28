# Task 4 Report — Local Identity, TOTP, Recovery Codes, and Sessions

## Status

Implemented the local identity service on baseline `840b856`: initial System Owner
creation, Argon2id passwords, envelope-encrypted member TOTP, one-use recovery
codes, one-time login challenges, replay-safe TOTP, server-side sessions,
recent-TOTP verification, logout, user-wide revocation, and password reset.

## RED / GREEN evidence

- RED: `go test ./internal/cryptobox -run 'TestIdentity|TestEnvelopeBinary'`
  failed to compile because identity envelope APIs and strict serialization did
  not exist. GREEN: the same command passed after adding domain-separated
  identity encryption and versioned envelope encoding.
- RED: `go test ./internal/identity` failed to compile because the identity
  service did not exist. GREEN: `go test ./internal/identity` passed after the
  model, repository, service, clock, and migration were implemented.
- RED: focused tests caught recovery-code sessions incorrectly receiving
  recent-TOTP status and permissive Argon2 parameter parsing. GREEN after
  persisting recent-TOTP only for TOTP logins and enforcing canonical bounded
  PHC parameters.
- RED: `TestChallengeExpiresAfterFiveMinutes` showed exact-boundary acceptance.
  GREEN after changing challenge expiry to an exclusive upper bound.
- RED: `TestResetPasswordInvalidatesOutstandingLoginChallenge` showed an
  outstanding pre-reset challenge could create a session. GREEN after binding
  challenges to the password hash and checking it inside the login transaction.

## Final verification

- `go test -race ./internal/identity ./internal/storage ./internal/cryptobox`
  passed: identity `24.674s`; storage and cryptobox passed.
- `go test ./...` passed for all Go packages.
- `go vet ./...` passed.
- `git diff --check` passed.

## Files

- Added `internal/platform/clock.go`.
- Added `internal/identity/model.go`, `repository.go`, `service.go`, and
  `service_test.go`.
- Added `internal/storage/migrations/0002_identity_state.sql`; updated migration
  tests for system roles, replay counters, idle expiry, and recent TOTP.
- Added `internal/cryptobox/envelope_binary.go`; extended envelope encryption
  and tests with `IdentityContext{UserID, Purpose}` and identity-only AAD.

## Self-review

- Argon2id current hashes are exactly 64 MiB / 3 iterations / parallelism 2 /
  16-byte salt / 32-byte output. The only accepted legacy form keeps the same
  memory, iterations, parallelism, and salt with a 16-byte output; it is
  transparently upgraded after the complete login succeeds.
- Unknown email and wrong password return the same `ErrInvalidCredentials` and
  both execute Argon2id verification using a dummy hash where needed.
- TOTP accepts only current ±1 30-second window; the persisted counter and
  session creation share a writer transaction, preventing concurrent replay.
- Recovery-code consumption and session creation share a writer transaction;
  concurrent use produces exactly one session.
- Session tokens contain 256 random bits and only SHA-256 hashes are stored;
  idle 8-hour and absolute 24-hour cutoffs, revocation, and 5-minute
  recent-TOTP behavior are covered.
- Raw SQLite bytes are checked for the password, TOTP seed, recovery code, and
  session-token fixtures.

## Concerns / accepted v1 constraints

- Login challenges intentionally live in a mutex-protected process-local
  five-minute store. Restart invalidates them, matching the approved v1
  single-instance boundary.
- Session resolution refreshes idle expiry in the single SQLite writer; this is
  correct for v1 but may warrant coalesced refresh writes at larger scale.

## Review remediation

### RED / GREEN

- RED: the new bounded-KDF and role-change identity tests initially failed to
  compile because `passwordKDF`, the exact legacy class, and
  `ChangeSystemRole` did not exist. GREEN: focused identity tests passed after
  adding the seam, the two-entry PHC allowlist, and the transactional role path.
- The KDF seam records calls without recording passwords. Unknown accounts,
  malformed PHCs, noncanonical leading-zero PHCs, unapproved high-cost PHCs,
  current wrong passwords, and legacy wrong passwords each make exactly one
  KDF call. Every call is fixed at 64 MiB / 3 iterations / parallelism 2 with a
  16-byte salt; output is 32 bytes except the single approved 16-byte legacy
  verifier.
- RED: `TestSessionIdleMigrationBackfillsOldRowsAndEnforcesNotNull` failed with
  `converting NULL to string is unsupported` against an old-schema session.
  GREEN: migration `0003_sessions_idle_not_null.sql` backfills old rows to the
  Unix epoch and rebuilds `sessions.idle_expires_at` with `NOT NULL`.
- The exact-five-minute recent-TOTP test was added before changing the predicate
  from `<=` to `<`. The role-change test performs a real `users.system_role`
  update and then observes `ErrSessionRevoked` for the prior session.

### Review verification

- `go test ./internal/identity ./internal/storage ./internal/cryptobox` passed.
- `go test -race ./internal/identity ./internal/storage ./internal/cryptobox`
  passed in the final run: identity cached, storage `4.972s`, cryptobox cached.
- `go test ./...`, `go vet ./...`, and `git diff --check` all passed.

### Review files and self-check

- Updated `internal/identity/model.go`, `repository.go`, `service.go`, and
  `service_test.go`.
- Updated `internal/storage/migrate_test.go` and added
  `internal/storage/migrations/0003_sessions_idle_not_null.sql`.
- `ChangeSystemRole` checks the actor's System Owner role, updates the target,
  and revokes target sessions in one writer transaction.
- `RevokeUserSessionsTx` is exposed as the narrow outer-transaction contract
  needed by later membership work; no Space behavior was added.
- PHC numeric fields must match the exact canonical parameter string, so leading
  zeros and every non-allowlisted cost are rejected without allocating their
  requested Argon2 resources.

## Final role-authorization review remediation

### RED / GREEN

- RED: `go test ./internal/identity -run 'TestChangeSystemRole'` failed to
  compile because `ErrRecentTOTPRequired` and `ErrLastSystemOwner` did not
  exist; the old API also interpreted the raw session fixture as a caller-
  supplied user ID.
- GREEN: the same focused command passed after `ChangeSystemRole` was changed
  to accept a raw actor session token and the repository transaction gained the
  complete authorization and last-owner checks.

### Security behavior

- `Service.ChangeSystemRole` hashes the raw session token with SHA-256 before
  repository access. No caller-supplied `SessionPrincipal` or actor user ID is
  trusted.
- One writer transaction validates that the actor session exists, is not
  revoked, is within idle and absolute deadlines, and has TOTP verification
  strictly newer than five minutes; it then verifies the actor is an active
  System Owner.
- The same transaction validates the requested role, prevents removal of the
  final active System Owner with `ErrLastSystemOwner`, updates the target role,
  and revokes every target session. Any error rolls all state back.
- Tests cover recovery-code sessions without recent TOTP, the sole-owner
  rollback preserving both role and session, safe promotion of a second owner
  followed by demotion of the first, and expired/revoked actor sessions.
  Sentinel errors are also checked not to contain the raw token.

### Final verification

- `go test -race ./internal/identity ./internal/storage ./internal/cryptobox`
  passed: identity `37.490s`; storage and cryptobox cached.
- `go test ./...`, `go vet ./...`, and `git diff --check` passed.
