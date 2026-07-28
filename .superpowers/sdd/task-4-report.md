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

- Argon2id is exactly 64 MiB / 3 iterations / parallelism 2 / 16-byte salt /
  32-byte output, with canonical parameter parsing and transparent upgrade.
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
