# OpsWarden v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-ready single-host OpsWarden v1 that manages assets and encrypted credentials for team members and scoped AI agents through React, REST, and MCP.

**Architecture:** A modular Go monolith owns all domain rules, SQLite access, envelope encryption, REST, and MCP. A React SPA is compiled into the Go image, while Caddy is the only public container and terminates HTTPS. Browser users authenticate with password, TOTP, and a server-side session cookie; agents use individually revocable bearer tokens.

**Tech Stack:** Go 1.26, React 19, TypeScript 5, Vite, SQLite through `modernc.org/sqlite`, `golang.org/x/crypto`, official MCP Go SDK, Caddy 2, Docker Compose 2, Vitest, React Testing Library, Playwright.

## Global Constraints

- The approved design is `docs/superpowers/specs/2026-07-28-opswarden-design.md`; implementation must not silently weaken it.
- Product copy uses “凭据库 / 凭据”; code and APIs use `credential`, never `secret` for the domain object.
- The application is a Go modular monolith with one SQLite writer and no network filesystem support.
- React browser authentication uses `__Host-opswarden_session` with `Secure; HttpOnly; SameSite=Strict; Path=/`; authentication tokens never enter browser storage.
- Agents authenticate independently and receive only per-Space scopes; service-side authorization never relies on Hermes tool filtering.
- Credential values, member TOTP seeds, session IDs, full Agent Tokens, and the master key must never appear in logs, errors, audit payloads, URLs, browser storage, or idempotency records.
- Every credential version uses XChaCha20-Poly1305 envelope encryption and authenticated context binding.
- Agent writes require an idempotency key; updates and deletes require `expected_version`; Agent delete is always soft delete.
- A credential read is returned only after its audit event is durably written.
- REST and MCP call the same application services and return the same domain outcomes.
- SQLite and the master key are backed up separately; only the SQLite Online Backup API may snapshot a running database.
- Commit after every task, and keep unrelated changes out of each commit.

---

## File Structure

```text
cmd/opswarden/main.go                  process startup and shutdown
internal/app/app.go                    dependency wiring and lifecycle
internal/config/config.go              validated runtime configuration
internal/platform/clock.go             injectable clock for expiry/TOTP tests
internal/storage/db.go                 SQLite connection and pragmas
internal/storage/migrate.go            embedded migration runner
internal/storage/migrations/*.sql      ordered schema migrations
internal/cryptobox/envelope.go         credential and TOTP envelope encryption
internal/identity/*                    password, TOTP, recovery code, sessions
internal/spaces/*                      Space membership and roles
internal/authorization/policy.go       centralized human/Agent decisions
internal/audit/*                       redacted durable audit events
internal/credentials/*                 credential model, repository, service
internal/assets/*                      asset model, repository, service
internal/agents/*                      agents, tokens, scopes, idempotency
internal/httpapi/*                     REST router, middleware, DTOs, errors
internal/mcpserver/server.go            MCP transport and tools
internal/backup/service.go             online backup, retention, restore checks
internal/health/service.go             public and admin health states
internal/webui/embed.go                embedded React production assets
web/src/*                              React SPA
web/tests/*                            component and API-client tests
tests/e2e/*                            Playwright browser tests
deploy/Dockerfile                      reproducible multi-stage image
deploy/compose.yaml                    OpsWarden and Caddy deployment
deploy/Caddyfile                       HTTPS proxy and response headers
docs/operations.md                     initialization, backup, restore, upgrade
```

## Task 1: Bootstrap the Go Service and React Build

**Files:**
- Create: `go.mod`
- Create: `cmd/opswarden/main.go`
- Create: `internal/app/app.go`
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `internal/webui/embed.go`
- Create: `internal/webui/dist/index.html`
- Create: `web/package.json`
- Create: `web/tsconfig.json`
- Create: `web/vite.config.ts`
- Create: `web/index.html`
- Create: `web/src/main.tsx`
- Create: `web/src/App.tsx`
- Create: `web/src/App.test.tsx`

**Interfaces:**
- Produces: `config.Load() (config.Config, error)`.
- Produces: `app.New(config.Config) (*app.App, error)`.
- Produces: `(*app.App).Handler() http.Handler`, `Run(context.Context) error`, and `Close() error`.
- Produces: an embedded SPA fallback handler at `webui.Handler() http.Handler`.

- [ ] **Step 1: Write failing configuration and React smoke tests**

```go
func TestLoadRejectsMissingDataDir(t *testing.T) {
    t.Setenv("OPSWARDEN_DATA_DIR", "")
    _, err := Load()
    if !errors.Is(err, ErrDataDirRequired) { t.Fatalf("got %v", err) }
}
```

```tsx
it("renders the product name", () => {
  render(<App />);
  expect(screen.getByRole("heading", { name: "OpsWarden" })).toBeVisible();
});
```

- [ ] **Step 2: Run the tests and confirm the scaffold is absent**

Run: `go test ./internal/config && cd web && npm test -- --run`

Expected: Go fails because `Load` is undefined; Vitest fails because the web package is not installed.

- [ ] **Step 3: Add the minimal runnable service and SPA**

```go
type Config struct {
    ListenAddr string
    DataDir    string
    MasterKeyFile string
}

type App struct { handler http.Handler }
func New(cfg config.Config) (*App, error)
func (a *App) Handler() http.Handler
func (a *App) Run(ctx context.Context) error
func (a *App) Close() error
```

`main.go` must load configuration, construct the app, handle `SIGINT`/`SIGTERM`, and shut down with a 10-second deadline. `App.tsx` must render only a heading and a loading-safe root shell. `vite.config.ts` must output to `../internal/webui/dist`.

- [ ] **Step 4: Verify both toolchains**

Run: `go test ./... && cd web && npm install && npm test -- --run && npm run build`

Expected: all tests pass and `internal/webui/dist/index.html` is replaced by the Vite build.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum cmd internal/config internal/app internal/webui web
git commit -m "build: bootstrap Go service and React app"
```

## Task 2: Validate the Master Key and Implement Envelope Encryption

**Files:**
- Create: `internal/cryptobox/envelope.go`
- Create: `internal/cryptobox/envelope_test.go`
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

**Interfaces:**
- Consumes: `config.Config.MasterKeyFile`.
- Produces: `cryptobox.LoadMasterKey(path string) ([32]byte, error)`.
- Produces: `(*Box).EncryptCredential(ctx CredentialContext, plaintext []byte) (Envelope, error)`.
- Produces: `(*Box).DecryptCredential(ctx CredentialContext, env Envelope) ([]byte, error)`.
- Produces: `(*Box).RewrapDataKey(oldCtx, newCtx CredentialContext, env Envelope, newMaster [32]byte) (Envelope, error)`.

- [ ] **Step 1: Write failing cryptographic boundary tests**

```go
func TestEnvelopeRejectsMovedCiphertext(t *testing.T) {
    box := newTestBox(t)
    env, _ := box.EncryptCredential(CredentialContext{CredentialID:"c1", SpaceID:"s1", Version:1, Type:"login"}, []byte(`{"password":"p"}`))
    _, err := box.DecryptCredential(CredentialContext{CredentialID:"c2", SpaceID:"s1", Version:1, Type:"login"}, env)
    if !errors.Is(err, ErrAuthentication) { t.Fatalf("got %v", err) }
}

func TestLoadMasterKeyRejectsGroupReadableFile(t *testing.T) {
    path := filepath.Join(t.TempDir(), "master.key")
    raw := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
    if err := os.WriteFile(path, []byte(raw), 0o640); err != nil { t.Fatal(err) }
    _, err := LoadMasterKey(path)
    if !errors.Is(err, ErrKeyPermissions) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Verify the tests fail**

Run: `go test ./internal/cryptobox ./internal/config`

Expected: compile failure because `Envelope`, `Box`, and key validation do not exist.

- [ ] **Step 3: Implement exact envelope fields and key checks**

```go
type CredentialContext struct {
    CredentialID string
    SpaceID string
    Version uint64
    Type string
}
type Envelope struct {
    Ciphertext []byte
    Nonce [24]byte
    WrappedDataKey []byte
    WrapNonce [24]byte
}
```

Use `chacha20poly1305.NewX`, a random 32-byte data key per version, independent 24-byte nonces, and canonical length-prefixed AAD. Accept only a regular 0600-or-stricter key file containing base64 for exactly 32 bytes. Zero temporary data-key byte slices after use.

- [ ] **Step 4: Exercise tamper detection, context binding, round-trip, and rewrap**

Run: `go test -race ./internal/cryptobox ./internal/config`

Expected: all tests pass; altered ciphertext, nonce, wrapped key, or context returns `ErrAuthentication`.

- [ ] **Step 5: Commit**

```bash
git add internal/cryptobox internal/config
git commit -m "feat: add envelope encryption and master key validation"
```

## Task 3: Add SQLite Schema, Migrations, and Transaction Primitives

**Files:**
- Create: `internal/storage/db.go`
- Create: `internal/storage/db_test.go`
- Create: `internal/storage/migrate.go`
- Create: `internal/storage/migrate_test.go`
- Create: `internal/storage/migrations/0001_initial.sql`
- Modify: `internal/app/app.go`

**Interfaces:**
- Consumes: `config.Config.DataDir`.
- Produces: `storage.Open(path string) (*storage.DB, error)`, where `DB.Writer` is a single-connection write handle and `DB.Reader` is a bounded read pool.
- Produces: `storage.Migrate(context.Context, *sql.DB) error`.
- Produces: `storage.WithTx(ctx context.Context, db *storage.DB, fn func(*sql.Tx) error) error`, always using `DB.Writer`.

- [ ] **Step 1: Write failing migration and pragma tests**

```go
func TestOpenEnablesRequiredPragmas(t *testing.T) {
    db := openTempDB(t)
    assertPragma(t, db, "journal_mode", "wal")
    assertPragma(t, db, "foreign_keys", "1")
    assertPragma(t, db, "busy_timeout", "5000")
}

func TestInitialMigrationCreatesAllTables(t *testing.T) {
    db := openTempDB(t)
    for _, table := range []string{"users","user_totp","recovery_codes","sessions","spaces","space_memberships","agents","agent_tokens","agent_space_grants","assets","credentials","credential_versions","asset_credentials","audit_events","idempotency_records","backup_runs"} {
        assertTableExists(t, db, table)
    }
}
```

- [ ] **Step 2: Verify the storage tests fail**

Run: `go test ./internal/storage`

Expected: compile failure because `Open` and `Migrate` are undefined.

- [ ] **Step 3: Implement the schema and migration runner**

The migration must encode foreign keys, unique normalized emails, immutable credential version numbers, normalized `credential_tags` and `asset_tags`, Space-local asset/credential links, hashed session/token columns, soft-delete timestamps, idempotency uniqueness `(agent_id, endpoint, key_hash)`, and indexes for Space, type, tags lookup, audit time, and expiration cleanup. `Open` must return a `DB` containing one writer connection and a reader pool capped at four connections; both handles use the same SQLite file and required pragmas.

- [ ] **Step 4: Verify migration idempotence and rollback**

Run: `go test -race ./internal/storage`

Expected: a second migration run changes nothing; an intentionally failing migration rolls back its schema version.

- [ ] **Step 5: Commit**

```bash
git add internal/storage internal/app/app.go
git commit -m "feat: add SQLite schema and migration runner"
```

## Task 4: Implement Local Identity, TOTP, Recovery Codes, and Sessions

**Files:**
- Create: `internal/platform/clock.go`
- Create: `internal/identity/model.go`
- Create: `internal/identity/repository.go`
- Create: `internal/identity/service.go`
- Create: `internal/identity/service_test.go`

**Interfaces:**
- Consumes: `cryptobox.Box`, `storage.WithTx`, and `platform.Clock`.
- Produces: `identity.Service.CreateInitialOwner`, `BeginLogin`, `CompleteLogin`, `VerifyRecentTOTP`, `Logout`, `RevokeUserSessions`, and `ResetPassword`.
- Produces: `identity.SessionPrincipal{UserID, SessionID, IssuedAt, RecentTOTPAt}`.

- [ ] **Step 1: Write failing identity lifecycle tests**

```go
func TestLoginRequiresPasswordThenTOTP(t *testing.T) {
    h := newIdentityHarness(t)
    if _, err := h.service.BeginLogin(h.ctx, h.email, "wrong"); !errors.Is(err, ErrInvalidCredentials) { t.Fatalf("got %v", err) }
    challenge, err := h.service.BeginLogin(h.ctx, h.email, h.password)
    if err != nil { t.Fatal(err) }
    session, err := h.service.CompleteLogin(h.ctx, challenge.ID, h.currentTOTP())
    if err != nil || session.RawToken == "" { t.Fatalf("session=%+v err=%v", session, err) }
}

func TestRecoveryCodeIsSingleUse(t *testing.T) {
    h := newIdentityHarness(t)
    code := h.firstRecoveryCode()
    if _, err := h.loginWithRecovery(code); err != nil { t.Fatal(err) }
    if _, err := h.loginWithRecovery(code); !errors.Is(err, ErrInvalidRecoveryCode) { t.Fatalf("got %v", err) }
}

func TestRoleChangeRevokesSessions(t *testing.T) {
    h := newIdentityHarness(t)
    session := h.login()
    h.changeRole()
    if _, err := h.service.ResolveSession(h.ctx, session.RawToken); !errors.Is(err, ErrSessionRevoked) { t.Fatalf("got %v", err) }
}

func TestUserTOTPSeedIsNotPlaintextInDatabase(t *testing.T) {
    h := newIdentityHarness(t)
    raw, err := os.ReadFile(h.databasePath)
    if err != nil { t.Fatal(err) }
    if bytes.Contains(raw, []byte(h.totpSeed)) { t.Fatal("TOTP seed found in database") }
}
```

- [ ] **Step 2: Verify the identity tests fail**

Run: `go test ./internal/identity`

Expected: compile failure because the identity service does not exist.

- [ ] **Step 3: Implement the identity contracts**

```go
type LoginChallenge struct { ID string; ExpiresAt time.Time }
type Session struct { RawToken string; ExpiresAt time.Time; IdleExpiresAt time.Time }
type CreateOwnerInput struct { Email, Password, TOTPSeed string; SourceIP netip.Addr }
```

Use Argon2id with the approved parameters, encrypted TOTP seeds with identity-specific AAD, hashed one-use recovery codes, hashed 256-bit session tokens, 8-hour idle expiry, 24-hour absolute expiry, and a 5-minute recent-TOTP window. Permit initial-owner creation only when no user exists and the source address is loopback or configured internal CIDR.

- [ ] **Step 4: Run identity and storage tests under the race detector**

Run: `go test -race ./internal/identity ./internal/storage ./internal/cryptobox`

Expected: all tests pass and the database byte scan cannot find password, TOTP seed, recovery code, or session token fixtures.

- [ ] **Step 5: Commit**

```bash
git add internal/platform internal/identity internal/storage/migrations
git commit -m "feat: add local identity and secure sessions"
```

## Task 5: Implement Spaces and Central Authorization

**Files:**
- Create: `internal/spaces/model.go`
- Create: `internal/spaces/repository.go`
- Create: `internal/spaces/service.go`
- Create: `internal/spaces/service_test.go`
- Create: `internal/authorization/policy.go`
- Create: `internal/authorization/policy_test.go`

**Interfaces:**
- Produces: `spaces.Service.Create`, `AddMember`, `ChangeRole`, `RemoveMember`, `ListForUser`.
- Produces: `authorization.DecisionForHuman(principal, resource, action) Decision`.
- Produces: `authorization.DecisionForAgent(principal, resource, action) Decision`.
- Defines: `Action` constants for every credential, asset, membership, Agent, audit, backup, and settings operation.

- [ ] **Step 1: Write a table-driven permission matrix**

```go
tests := []struct{ role spaces.Role; action authorization.Action; allowed bool }{
    {spaces.Owner, authorization.ManageMembers, true},
    {spaces.Editor, authorization.DeleteCredential, true},
    {spaces.Editor, authorization.ManageMembers, false},
    {spaces.Reader, authorization.ReadCredential, true},
    {spaces.Reader, authorization.UpdateCredential, false},
}
```

Add Agent cases proving that Space scope and label filters only narrow access and that unauthorized resource IDs resolve to a concealed not-found decision.

- [ ] **Step 2: Verify the matrix fails**

Run: `go test ./internal/spaces ./internal/authorization`

Expected: compile failure because roles, actions, and policy functions do not exist.

- [ ] **Step 3: Implement roles and one centralized policy engine**

```go
type Resource struct { SpaceID, ResourceID string; Labels map[string]string }
type Decision struct { Allowed bool; Conceal bool; Reason Code }
type AgentPrincipal struct { AgentID string; Grants []Grant }
type Grant struct { SpaceID string; Scopes map[Scope]struct{}; Labels map[string]string }
type Scope string
```

Domain services must call this policy engine; handlers may perform an early check but cannot be the only enforcement point.

- [ ] **Step 4: Run exhaustive policy tests**

Run: `go test -race ./internal/spaces ./internal/authorization`

Expected: all human and Agent matrix rows pass, including cross-Space and label mismatch denial.

- [ ] **Step 5: Commit**

```bash
git add internal/spaces internal/authorization
git commit -m "feat: add spaces and centralized authorization"
```

## Task 6: Implement Durable Redacted Audit

**Files:**
- Create: `internal/audit/model.go`
- Create: `internal/audit/repository.go`
- Create: `internal/audit/service.go`
- Create: `internal/audit/service_test.go`

**Interfaces:**
- Produces: `audit.Event`, `audit.Actor`, `audit.ChangeFields`.
- Produces: `audit.Repository.AppendTx(context.Context, *sql.Tx, Event) error`.
- Produces: `audit.Service.RecordReadBeforeReturn(context.Context, Event) error`.
- Produces: `audit.Service.List(context.Context, Filter) ([]Event, Cursor, error)`.
- Produces: `audit.Service.PurgeBefore(context.Context, time.Time) (int64, error)` for the one-year retention job.

- [ ] **Step 1: Write failing redaction and durability tests**

```go
func TestEventRejectsSensitiveFieldNames(t *testing.T) {
    err := Validate(Event{ChangeFields: []string{"password"}})
    if !errors.Is(err, ErrSensitiveAuditField) { t.Fatalf("got %v", err) }
}

func TestReadFailsWhenAuditInsertFails(t *testing.T) {
    h := newAuditHarness(t)
    h.repository.FailNextInsert(ErrAuditUnavailable)
    value, err := h.readCredential()
    if !errors.Is(err, ErrAuditUnavailable) { t.Fatalf("got %v", err) }
    if len(value) != 0 { t.Fatalf("payload escaped: %q", value) }
}
```

- [ ] **Step 2: Verify the tests fail**

Run: `go test ./internal/audit`

Expected: compile failure because the audit model and repository do not exist.

- [ ] **Step 3: Implement the strict audit allowlist**

Allowed change-field names must be metadata-only, such as `display_name`, `tags`, `asset_links`, `credential_type`, and `expires_at`. Audit actor data stores user/Agent ID and only a short non-sensitive token/session fingerprint. Reject arbitrary maps and free-form structured values.

- [ ] **Step 4: Verify audit pagination and failure behavior**

Run: `go test -race ./internal/audit`

Expected: ordered cursor pagination passes; sensitive keys are rejected; injected write failure blocks the associated read.

- [ ] **Step 5: Commit**

```bash
git add internal/audit
git commit -m "feat: add durable redacted audit events"
```

## Task 7: Implement Credential CRUD, Versions, Idempotency, and Recycle Bin

**Files:**
- Create: `internal/credentials/model.go`
- Create: `internal/credentials/repository.go`
- Create: `internal/credentials/service.go`
- Create: `internal/credentials/service_test.go`
- Create: `internal/credentials/payloads.go`
- Create: `internal/credentials/payloads_test.go`

**Interfaces:**
- Consumes: authorization policy, cryptobox, audit, SQLite transactions, and clock.
- Produces: `credentials.Service.List`, `Get`, `Create`, `Update`, `Delete`, `Restore`, `PurgeExpired`.
- Produces: typed payload validation for login, API Token, SSH key, database, and TOTP.
- Produces: `credentials.Metadata` separately from `credentials.Decrypted`.

- [ ] **Step 1: Write failing credential behavior tests**

```go
func TestListNeverReturnsPayload(t *testing.T) {
    h := newCredentialHarness(t)
    rows, _, err := h.service.List(h.ctx, h.reader, ListFilter{SpaceID:h.spaceID})
    if err != nil { t.Fatal(err) }
    if _, exists := reflect.TypeOf(rows[0]).FieldByName("Payload"); exists { t.Fatal("metadata exposes payload") }
}

func TestCreateEncryptsPayloadAndCommitsAuditAtomically(t *testing.T) {
    h := newCredentialHarness(t)
    h.audit.FailNextInsert(ErrAuditUnavailable)
    _, err := h.service.Create(h.ctx, h.editor, h.createInput(), h.writeContext("idem-1"))
    if !errors.Is(err, ErrAuditUnavailable) || h.countCredentials() != 0 { t.Fatalf("err=%v rows=%d", err, h.countCredentials()) }
}

func TestUpdateRequiresExpectedVersion(t *testing.T) {
    h := newCredentialHarness(t)
    id := h.createCredential()
    _, err := h.service.Update(h.ctx, h.editor, UpdateInput{CredentialID:id, ExpectedVersion:0}, h.writeContext("idem-2"))
    if !errors.Is(err, ErrVersionConflict) { t.Fatalf("got %v", err) }
}

func TestAgentDeleteIsIdempotentSoftDelete(t *testing.T) {
    h := newCredentialHarness(t)
    id, version := h.createCredentialWithVersion()
    wc := h.agentWriteContext("idem-delete")
    if err := h.service.Delete(h.ctx, h.agent, id, version, wc); err != nil { t.Fatal(err) }
    if err := h.service.Delete(h.ctx, h.agent, id, version, wc); err != nil { t.Fatal(err) }
    if h.effectiveDeleteCount(id) != 1 { t.Fatal("delete was not idempotent") }
}

func TestCrossSpaceGetReturnsConcealedNotFound(t *testing.T) {
    h := newCredentialHarness(t)
    _, err := h.service.Get(h.ctx, h.otherSpaceReader, h.credentialID)
    if !errors.Is(err, ErrNotFound) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Verify the tests fail**

Run: `go test ./internal/credentials`

Expected: compile failure because the service and payload types do not exist.

- [ ] **Step 3: Implement the exact service boundary**

```go
type WriteContext struct { Actor audit.Actor; IdempotencyKey, Reason string }
type CreateInput struct { SpaceID, DisplayName string; Type Type; Tags map[string]string; AssetIDs []string; Payload json.RawMessage }
type UpdateInput struct { CredentialID string; ExpectedVersion uint64; DisplayName *string; Tags map[string]string; AssetIDs []string; Payload json.RawMessage }
type Metadata struct { ID, SpaceID, DisplayName string; Type Type; Version uint64; Tags map[string]string; AssetIDs []string; DeletedAt *time.Time }
type Decrypted struct { Metadata Metadata; Payload json.RawMessage }
```

Validate each payload with an explicit struct and reject unknown JSON fields. Store idempotency request hash, resulting resource ID, version, and status only. Writes and audit append share one transaction. Reads decrypt into a request-local buffer, durably append the successful audit event, and return the buffer only if the audit write succeeds.

- [ ] **Step 4: Run concurrency and plaintext-leak tests**

Run: `go test -race -count=20 ./internal/credentials`

Expected: all runs pass; only one concurrent update wins; fixture passwords, private keys, connection strings, and TOTP seeds are absent from raw DB bytes and idempotency rows.

- [ ] **Step 5: Commit**

```bash
git add internal/credentials
git commit -m "feat: add encrypted credential lifecycle"
```

## Task 8: Implement Asset Management and Credential Links

**Files:**
- Create: `internal/assets/model.go`
- Create: `internal/assets/repository.go`
- Create: `internal/assets/service.go`
- Create: `internal/assets/service_test.go`

**Interfaces:**
- Produces: `assets.Service.List`, `Get`, `Create`, `Update`, `Delete`.
- Produces: `assets.Service.ListCredentialMetadata`.
- Enforces: humans follow Space roles; Agents receive list/get only with asset scopes.

- [ ] **Step 1: Write failing asset and link tests**

```go
func TestCannotLinkAcrossSpaces(t *testing.T) {
    h := newAssetHarness(t)
    err := h.service.LinkCredential(h.ctx, h.owner, h.assetID, h.otherSpaceCredentialID)
    if !errors.Is(err, ErrCrossSpaceLink) { t.Fatalf("got %v", err) }
}
func TestAgentCannotMutateAsset(t *testing.T) {
    h := newAssetHarness(t)
    _, err := h.service.Update(h.ctx, h.agent, h.updateInput())
    if !errors.Is(err, authorization.ErrDenied) { t.Fatalf("got %v", err) }
}
func TestAssetListsOnlyAuthorizedCredentialMetadata(t *testing.T) {
    h := newAssetHarness(t)
    rows, err := h.service.ListCredentialMetadata(h.ctx, h.labelScopedAgent, h.assetID)
    if err != nil || len(rows) != 1 || rows[0].DisplayName != h.allowedDisplayName { t.Fatalf("rows=%+v err=%v", rows, err) }
}
```

- [ ] **Step 2: Verify the tests fail**

Run: `go test ./internal/assets`

Expected: compile failure because the asset service does not exist.

- [ ] **Step 3: Implement validated asset metadata**

```go
type Asset struct {
    ID, SpaceID, Name, Type, Hostname, OS, Environment, Status string
    IPs []netip.Addr
    Ports []uint16
    Tags map[string]string
    Notes string
    Version uint64
}
```

Require expected version on update/delete, validate IP and port values, and query credential links through metadata-only repository methods.

- [ ] **Step 4: Run asset, credential, and policy tests**

Run: `go test -race ./internal/assets ./internal/credentials ./internal/authorization`

Expected: all tests pass and cross-Space links are impossible at both service and foreign-key layers.

- [ ] **Step 5: Commit**

```bash
git add internal/assets
git commit -m "feat: add asset inventory and credential links"
```

## Task 9: Implement Agent Registration, Tokens, Grants, and Rate Limits

**Files:**
- Create: `internal/agents/model.go`
- Create: `internal/agents/repository.go`
- Create: `internal/agents/service.go`
- Create: `internal/agents/service_test.go`
- Create: `internal/agents/limiter.go`
- Create: `internal/agents/limiter_test.go`

**Interfaces:**
- Produces: `agents.Service.Create`, `IssueToken`, `RevokeToken`, `SetGrant`, `Authenticate`, `ListUsage`.
- Produces: `agents.AuthenticatedPrincipal`.
- Produces: `agents.Authenticator` interface so a short-lived JWT verifier can be added without changing domain services.
- Produces: `agents.Limiter.Allow(subject, operation, now) Decision`.

- [ ] **Step 1: Write failing token and grant tests**

```go
func TestTokenShownOnceAndStoredHashed(t *testing.T) {
    h := newAgentHarness(t)
    issued, err := h.service.IssueToken(h.ctx, h.agentID, h.expiry)
    if err != nil || issued.Raw == "" { t.Fatalf("issued=%+v err=%v", issued, err) }
    stored := h.repository.TokenRow(issued.ID)
    if stored.HashHex != sha256Hex(issued.Raw) || stored.Raw != "" { t.Fatalf("stored=%+v", stored) }
}
func TestRevocationTakesEffectOnNextRequest(t *testing.T) {
    h := newAgentHarness(t)
    issued := h.issueToken()
    if _, err := h.service.Authenticate(h.ctx, issued.Raw); err != nil { t.Fatal(err) }
    if err := h.service.RevokeToken(h.ctx, issued.ID); err != nil { t.Fatal(err) }
    if _, err := h.service.Authenticate(h.ctx, issued.Raw); !errors.Is(err, ErrTokenRevoked) { t.Fatalf("got %v", err) }
}
func TestExpiredTokenFails(t *testing.T) {
    h := newAgentHarness(t)
    issued := h.issueToken()
    h.clock.Advance(25 * time.Hour)
    if _, err := h.service.Authenticate(h.ctx, issued.Raw); !errors.Is(err, ErrTokenExpired) { t.Fatalf("got %v", err) }
}
func TestGrantCannotContainUnknownScope(t *testing.T) {
    h := newAgentHarness(t)
    err := h.service.SetGrant(h.ctx, h.agentID, Grant{SpaceID:h.spaceID, Scopes:[]authorization.Scope{"root"}})
    if !errors.Is(err, ErrInvalidScope) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Verify the tests fail**

Run: `go test ./internal/agents`

Expected: compile failure because Agent service and limiter do not exist.

- [ ] **Step 3: Implement opaque bearer tokens and scoped grants**

```go
type IssuedToken struct { ID, Prefix, Raw string; ExpiresAt time.Time }
type Grant struct { SpaceID string; Scopes []authorization.Scope; RequiredLabels map[string]string }
type AuthenticatedPrincipal struct { AgentID, TokenID, TokenPrefix string; Grants []Grant }
```

Generate an `owat_` prefix followed by 32 random bytes encoded base64url. Persist SHA-256 only. Add separate bounded token buckets for authentication failure, credential list, credential read, and credential write.

- [ ] **Step 4: Verify immediate revocation and limiter isolation**

Run: `go test -race ./internal/agents`

Expected: all tests pass; one Agent exhausting read limits does not block another Agent or human session.

- [ ] **Step 5: Commit**

```bash
git add internal/agents
git commit -m "feat: add scoped agent identities"
```

## Task 10: Expose the REST API and Browser Authentication

**Files:**
- Create: `internal/httpapi/router.go`
- Create: `internal/httpapi/router_test.go`
- Create: `internal/httpapi/auth_handlers.go`
- Create: `internal/httpapi/credential_handlers.go`
- Create: `internal/httpapi/asset_handlers.go`
- Create: `internal/httpapi/agent_handlers.go`
- Create: `internal/httpapi/audit_handlers.go`
- Create: `internal/httpapi/middleware.go`
- Create: `internal/httpapi/errors.go`
- Create: `internal/httpapi/dto.go`
- Modify: `internal/app/app.go`

**Interfaces:**
- Consumes: all domain services from Tasks 4–9.
- Produces: `/api/v1` routes and stable error envelope.
- Produces: `httpapi.New(Dependencies) http.Handler`.

- [ ] **Step 1: Write failing HTTP contract tests**

```go
func TestCredentialListOmitsPayload(t *testing.T) {
    h := newHTTPHarness(t)
    body := h.getAsUser("/api/v1/spaces/"+h.spaceID+"/credentials")
    if bytes.Contains(body, []byte("payload")) || bytes.Contains(body, []byte(h.fixturePassword)) { t.Fatalf("unsafe body: %s", body) }
}
func TestUnauthorizedCredentialIs404(t *testing.T) {
    h := newHTTPHarness(t)
    res := h.getResponseAsUser("/api/v1/spaces/"+h.otherSpaceID+"/credentials/"+h.otherCredentialID)
    assertAPIError(t, res, http.StatusNotFound, "NOT_FOUND")
}
func TestAgentWriteRequiresIdempotencyHeader(t *testing.T) {
    h := newHTTPHarness(t)
    res := h.postAsAgent("/api/v1/spaces/"+h.spaceID+"/credentials", h.validCreateBody(), nil)
    assertAPIError(t, res, http.StatusBadRequest, "INVALID_REQUEST")
}
func TestSessionCookieHasRequiredAttributes(t *testing.T) {
    cookie := newHTTPHarness(t).loginCookie()
    if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" { t.Fatalf("cookie=%+v", cookie) }
}
func TestStateChangeRequiresCSRF(t *testing.T) {
    h := newHTTPHarness(t)
    res := h.postAsUserWithoutCSRF("/api/v1/spaces", []byte(`{"name":"x"}`))
    assertAPIError(t, res, http.StatusForbidden, "PERMISSION_DENIED")
}
func TestErrorsAndLogsRedactFixtureValues(t *testing.T) {
    h := newHTTPHarness(t)
    h.postMalformedCredentialContaining(h.fixturePassword)
    if strings.Contains(h.logs.String(), h.fixturePassword) { t.Fatal("fixture leaked to logs") }
}
```

- [ ] **Step 2: Verify the HTTP tests fail**

Run: `go test ./internal/httpapi`

Expected: compile failure because the router does not exist.

- [ ] **Step 3: Implement routes, middleware, DTOs, and exact errors**

Middleware order: request ID, recovery, security headers, structured redacted logging, rate limit, authentication, CSRF for browser writes, then handler. Map domain errors to the approved codes and never place request bodies in logs. Set `Cache-Control: no-store` on authentication and credential responses.

- [ ] **Step 4: Run the complete Go API suite**

Run: `go test -race ./internal/... ./cmd/...`

Expected: all tests pass; malformed payloads, unknown fields, cross-Space IDs, missing versions, and repeated idempotency keys match the documented outcomes.

- [ ] **Step 5: Commit**

```bash
git add internal/httpapi internal/app/app.go
git commit -m "feat: expose authenticated REST API"
```

## Task 11: Expose MCP Streamable HTTP for Hermes

**Files:**
- Create: `internal/mcpserver/server.go`
- Create: `internal/mcpserver/server_test.go`
- Create: `internal/mcpserver/tools.go`
- Modify: `internal/app/app.go`
- Create: `docs/hermes-agent.md`

**Interfaces:**
- Consumes: Agent authentication, credential service, and asset service.
- Produces: `/mcp` Streamable HTTP endpoint.
- Produces tools: `credential_list`, `credential_get`, `credential_create`, `credential_update`, `credential_delete`, `totp_generate`, `asset_list`, `asset_get`.

- [ ] **Step 1: Write failing MCP parity tests**

```go
func TestToolsExposeExactApprovedNames(t *testing.T) {
    got := newMCPHarness(t).discoveredToolNames()
    want := []string{"asset_get","asset_list","credential_create","credential_delete","credential_get","credential_list","credential_update","totp_generate"}
    if !slices.Equal(got, want) { t.Fatalf("got %v want %v", got, want) }
}
func TestCredentialGetMatchesRESTDomainResult(t *testing.T) {
    h := newMCPHarness(t)
    mcpResult := h.callCredentialGet(h.agentToken, h.credentialID)
    restResult := h.callRESTCredentialGet(h.agentToken, h.credentialID)
    if !reflect.DeepEqual(restResult, mcpResult) { t.Fatalf("rest=%+v mcp=%+v", restResult, mcpResult) }
}
func TestDeleteRequiresExactIDVersionReasonAndIdempotencyKey(t *testing.T) {
    h := newMCPHarness(t)
    for _, missing := range []string{"credential_id","expected_version","reason","idempotency_key"} {
        if err := h.callDeleteWithMissingField(missing); !errors.Is(err, ErrInvalidToolInput) { t.Fatalf("%s: %v", missing, err) }
    }
}
func TestReadOnlyAgentCannotDiscoverWriteSuccess(t *testing.T) {
    h := newMCPHarness(t)
    err := h.callCredentialCreate(h.readOnlyToken, h.validCreateInput())
    if !errors.Is(err, credentials.ErrNotFound) { t.Fatalf("got %v", err) }
}
```

- [ ] **Step 2: Verify MCP tests fail**

Run: `go test ./internal/mcpserver`

Expected: compile failure because the MCP server does not exist.

- [ ] **Step 3: Implement tools as thin adapters**

Each input schema uses explicit fields and descriptions. `credential_list` returns metadata only. `credential_get` and `totp_generate` mark their output as sensitive in descriptions and set no-cache transport headers. Disable MCP prompts, resources, and sampling. Do not opt into parallel tool calls for this server because reads and writes share authorization and SQLite state.

- [ ] **Step 4: Verify with the official SDK client and Hermes config shape**

Run: `go test -race ./internal/mcpserver ./internal/httpapi`

Expected: official Go MCP client discovers eight tools over HTTP, authenticated calls succeed, revoked tokens fail immediately, and REST/MCP parity tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/mcpserver internal/app/app.go docs/hermes-agent.md
git commit -m "feat: add Hermes-compatible MCP server"
```

## Task 12: Build the React Authentication and Application Shell

**Files:**
- Create: `web/src/api/client.ts`
- Create: `web/src/api/types.ts`
- Create: `web/src/auth/AuthProvider.tsx`
- Create: `web/src/auth/SetupPage.tsx`
- Create: `web/src/auth/LoginPage.tsx`
- Create: `web/src/auth/LoginPage.test.tsx`
- Create: `web/src/layout/AppShell.tsx`
- Create: `web/src/layout/Sidebar.tsx`
- Create: `web/src/spaces/SpaceSwitcher.tsx`
- Modify: `web/src/App.tsx`
- Modify: `web/package.json`

**Interfaces:**
- Consumes: `/api/v1/auth/*`, `/api/v1/me`, and `/api/v1/spaces`.
- Produces: `api.request<T>()` with credentials included, in-memory CSRF token, stable error decoding, and `AuthProvider`.
- Produces: protected routes for 概览、凭据库、资产、Agent、审计日志、成员与权限、设置.

- [ ] **Step 1: Write failing login and shell tests**

```tsx
it("never writes auth material to browser storage", async () => {
  const local = vi.spyOn(Storage.prototype, "setItem");
  await completePasswordAndTotpLogin();
  expect(local).not.toHaveBeenCalled();
});

it("renders 凭据库 in the primary navigation", async () => {
  renderAuthenticated(<App />);
  expect(await screen.findByRole("link", { name: "凭据库" })).toBeVisible();
});
```

- [ ] **Step 2: Verify the tests fail**

Run: `cd web && npm test -- --run src/auth/LoginPage.test.tsx`

Expected: failures because the provider, login flow, and shell do not exist.

- [ ] **Step 3: Implement the two-step login and responsive shell**

The API client must use `credentials: "include"`, attach the in-memory CSRF header on writes, redirect on session expiry, and render request IDs for support without rendering raw server details. `SetupPage` is reachable only while the server reports no owner and guides password, TOTP enrollment, recovery-code confirmation, and initial Space creation. The sidebar uses approved Chinese labels and the current Space switcher.

- [ ] **Step 4: Run frontend tests and production build**

Run: `cd web && npm test -- --run && npm run build`

Expected: all tests pass; production assets build into `internal/webui/dist`; source and output contain no `localStorage.setItem` or `sessionStorage.setItem`.

- [ ] **Step 5: Commit**

```bash
git add web internal/webui/dist
git commit -m "feat: add React authentication and app shell"
```

## Task 13: Build Credential and Asset React Workflows

**Files:**
- Create: `web/src/credentials/CredentialListPage.tsx`
- Create: `web/src/credentials/CredentialDrawer.tsx`
- Create: `web/src/credentials/CredentialForm.tsx`
- Create: `web/src/credentials/RecycleBinPage.tsx`
- Create: `web/src/credentials/credentials.test.tsx`
- Create: `web/src/assets/AssetListPage.tsx`
- Create: `web/src/assets/AssetDetailPage.tsx`
- Create: `web/src/assets/AssetForm.tsx`
- Create: `web/src/assets/assets.test.tsx`
- Modify: `web/src/App.tsx`

**Interfaces:**
- Consumes: REST credential and asset endpoints.
- Produces: list/filter, typed create/edit, explicit reveal, soft delete, restore, asset CRUD, and bidirectional links.

- [ ] **Step 1: Write failing user-flow tests**

```tsx
it("lists credential metadata without fetching payload", async () => {
  const api = mockCredentialList();
  renderCredentialPage(api);
  await screen.findByText("orders database");
  expect(api.getCredential).not.toHaveBeenCalled();
});
it("audits only after the user clicks 显示", async () => {
  const api = mockCredentialList();
  renderCredentialPage(api);
  await userEvent.click(await screen.findByText("orders database"));
  expect(api.getCredential).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "显示" }));
  expect(api.getCredential).toHaveBeenCalledTimes(1);
});
it("uses the Chinese label 新建凭据", async () => {
  renderCredentialPage(mockCredentialList());
  expect(screen.getByRole("button", { name: "新建凭据" })).toBeVisible();
  expect(screen.queryByText("新建秘密")).toBeNull();
});
it("shows a version conflict without overwriting the form", async () => {
  const api = mockVersionConflict();
  renderCredentialEdit(api);
  await userEvent.type(screen.getByLabelText("显示名称"), " revised");
  await userEvent.click(screen.getByRole("button", { name: "保存" }));
  expect(screen.getByDisplayValue(/revised$/)).toBeVisible();
  expect(screen.getByText(/版本冲突/)).toBeVisible();
});
it("creates a credential prelinked from an asset", async () => {
  renderAssetDetail(mockAsset("asset-1", "space-1"));
  await userEvent.click(screen.getByRole("button", { name: "新建凭据" }));
  expect(screen.getByLabelText("关联资产")).toHaveValue("asset-1");
  expect(screen.getByLabelText("Space")).toHaveValue("space-1");
});
it("requires recent TOTP before permanent purge", async () => {
  renderRecycleBinAsSystemOwner(mockRecentTOTPRequired());
  await userEvent.click(screen.getByRole("button", { name: "永久删除" }));
  expect(screen.getByRole("dialog", { name: "重新验证 TOTP" })).toBeVisible();
});
```

- [ ] **Step 2: Verify tests fail**

Run: `cd web && npm test -- --run src/credentials src/assets`

Expected: failures because the workflow components do not exist.

- [ ] **Step 3: Implement typed forms and safe reveal behavior**

Use a discriminated union keyed by `credentialType`. Keep decrypted payload only in drawer component state, clear it on close/Space change/session loss, set copy feedback without rereading the clipboard, and never place values in query strings. Require typed confirmation for delete. Permanent purge appears only in the recycle bin for `System Owner` and goes through the recent-TOTP challenge.

- [ ] **Step 4: Run component tests and build**

Run: `cd web && npm test -- --run && npm run build`

Expected: all workflows pass with keyboard access; build succeeds; searches over built assets find no credential fixture values.

- [ ] **Step 5: Commit**

```bash
git add web/src/credentials web/src/assets web/src/App.tsx internal/webui/dist
git commit -m "feat: add credential and asset workflows"
```

## Task 14: Build Agent, Audit, Membership, and Settings UI

**Files:**
- Create: `web/src/agents/AgentListPage.tsx`
- Create: `web/src/agents/AgentForm.tsx`
- Create: `web/src/agents/TokenRevealDialog.tsx`
- Create: `web/src/agents/agents.test.tsx`
- Create: `web/src/audit/AuditPage.tsx`
- Create: `web/src/audit/audit.test.tsx`
- Create: `web/src/members/MembersPage.tsx`
- Create: `web/src/settings/SettingsPage.tsx`
- Modify: `web/src/App.tsx`

**Interfaces:**
- Consumes: Agent, audit, Space membership, health, and backup endpoints.
- Produces: one-time Token display, grants, revocation, audit filters, member roles, and admin status.

- [ ] **Step 1: Write failing privileged-workflow tests**

```tsx
it("shows an Agent token once and never refetches it", async () => {
  const api = mockIssueToken("owat_fixture");
  renderAgents(api);
  await userEvent.click(screen.getByRole("button", { name: "创建 Token" }));
  expect(screen.getByText("owat_fixture")).toBeVisible();
  await userEvent.click(screen.getByRole("button", { name: "关闭" }));
  expect(screen.queryByText("owat_fixture")).toBeNull();
  expect(api.issueToken).toHaveBeenCalledTimes(1);
});
it("requires recent TOTP before a privileged action", async () => {
  renderMembers(mockRecentTOTPRequired());
  await userEvent.click(screen.getByRole("button", { name: "移除成员" }));
  expect(screen.getByRole("dialog", { name: "重新验证 TOTP" })).toBeVisible();
});
it("filters audit by actor action and resource", async () => {
  const api = mockAudit();
  renderAudit(api);
  await userEvent.selectOptions(screen.getByLabelText("动作"), "credential.read");
  expect(api.list).toHaveBeenLastCalledWith(expect.objectContaining({ action: "credential.read" }));
});
it("prevents an Editor from seeing membership controls", async () => {
  renderMembers(mockMemberRole("Editor"));
  expect(screen.queryByRole("button", { name: "添加成员" })).toBeNull();
});
```

- [ ] **Step 2: Verify tests fail**

Run: `cd web && npm test -- --run src/agents src/audit`

Expected: failures because privileged pages are absent.

- [ ] **Step 3: Implement capability-driven administration pages**

The raw Agent Token exists only inside `TokenRevealDialog` state and is erased on close. Scope selection is grouped by Space and displays tag constraints. Audit tables render request ID, actor, action, resource, result, IP, and time, but no arbitrary JSON payload.

- [ ] **Step 4: Run the frontend suite**

Run: `cd web && npm test -- --run && npm run build`

Expected: all tests pass; role-limited controls are absent; Token reveal and recent-TOTP flows pass.

- [ ] **Step 5: Commit**

```bash
git add web/src/agents web/src/audit web/src/members web/src/settings web/src/App.tsx internal/webui/dist
git commit -m "feat: add administration and audit UI"
```

## Task 15: Implement Online Backup, Retention, and Health

**Files:**
- Create: `internal/backup/service.go`
- Create: `internal/backup/service_test.go`
- Create: `internal/health/service.go`
- Create: `internal/health/service_test.go`
- Create: `internal/httpapi/backup_handlers.go`
- Create: `internal/httpapi/health_handlers.go`
- Modify: `internal/httpapi/router.go`
- Modify: `internal/app/app.go`

**Interfaces:**
- Produces: `backup.Service.Run`, `ApplyRetention`, `Verify`, `ListRuns`.
- Produces: `health.Service.Liveness`, `Detailed`.
- Exposes: unauthenticated `/health/live` and admin-only `/api/v1/health`, `/api/v1/backups`.

- [ ] **Step 1: Write failing backup and health tests**

```go
func TestBackupUsesConsistentSnapshotDuringWrite(t *testing.T) {
    h := newBackupHarness(t)
    h.beginConcurrentCredentialWrite()
    path, err := h.service.Run(h.ctx)
    if err != nil { t.Fatal(err) }
    if state := h.snapshotState(path); state != "before" && state != "after" { t.Fatalf("torn state %q", state) }
}
func TestRetentionKeepsSevenDailyFourWeeklySixMonthly(t *testing.T) {
    h := newBackupHarness(t)
    kept := h.service.ApplyRetention(h.datedFixtures())
    if !reflect.DeepEqual(h.expectedRetentionSet(), kept) { t.Fatalf("got=%v want=%v", kept, h.expectedRetentionSet()) }
}
func TestBackupNeverContainsMasterKey(t *testing.T) {
    h := newBackupHarness(t)
    path, err := h.service.Run(h.ctx)
    if err != nil { t.Fatal(err) }
    raw, err := os.ReadFile(path)
    if err != nil { t.Fatal(err) }
    if bytes.Contains(raw, h.masterKeyBytes) { t.Fatal("master key found in backup") }
}
func TestDetailedHealthReportsDiskAndLastBackup(t *testing.T) {
    h := newHealthHarness(t)
    got := h.service.Detailed(h.ctx)
    if got.DiskFreeBytes == 0 || got.LastBackupAt.IsZero() || got.Database != "ok" { t.Fatalf("health=%+v", got) }
}
```

- [ ] **Step 2: Verify tests fail**

Run: `go test ./internal/backup ./internal/health ./internal/httpapi`

Expected: compile failure because backup and detailed health services do not exist.

- [ ] **Step 3: Implement online backup and deterministic retention**

Use the SQLite backup API through the selected driver, write to a temporary file in the backup directory, run `PRAGMA integrity_check`, calculate SHA-256, then atomically rename. Record success/failure in `backup_runs`. The app lifecycle starts one daily maintenance scheduler that runs backup, credential recycle-bin purge after 30 days, audit purge after one year, expired session/idempotency cleanup, and retention. The liveness endpoint exposes only status; detailed health includes version, uptime, DB/WAL state, disk space, migration, and latest backup without key fingerprints.

- [ ] **Step 4: Run backup, storage, and API tests**

Run: `go test -race ./internal/backup ./internal/health ./internal/storage ./internal/httpapi`

Expected: all tests pass, corrupted snapshots fail verification, and retention preserves the exact approved windows.

- [ ] **Step 5: Commit**

```bash
git add internal/backup internal/health internal/httpapi internal/app/app.go
git commit -m "feat: add verified backups and health reporting"
```

## Task 16: Add Docker Compose, Caddy, and Operational Documentation

**Files:**
- Create: `deploy/Dockerfile`
- Create: `deploy/compose.yaml`
- Create: `deploy/Caddyfile`
- Create: `deploy/.env.example`
- Create: `docs/operations.md`
- Create: `docs/security-model.md`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: the built Go binary, React build, runtime config, `/health/live`.
- Produces: a two-container single-host deployment with only Caddy port 443 exposed.

- [ ] **Step 1: Write deployment assertions**

```bash
docker compose -f deploy/compose.yaml config
docker build -f deploy/Dockerfile .
```

Expected before implementation: both commands fail because deployment files are absent.

- [ ] **Step 2: Add the hardened multi-stage image and Compose topology**

The image must build React, compile a static Linux Go binary, run as a numeric non-root user, use a read-only root filesystem, mount `/var/lib/opswarden` read-write, mount `/run/secrets/master.key` read-only, and include a healthcheck. Compose exposes only Caddy `443:443`; SQLite and the Go listener have no host port.

- [ ] **Step 3: Add Caddy security controls and exact operator procedures**

`Caddyfile` must force HTTPS, proxy to `opswarden`, set CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`, and limit request bodies at the application layer. `operations.md` must give exact commands for key generation, permission setup, initial owner creation from loopback/internal CIDR, backup, quarterly restore drill, upgrade, rollback, and emergency Token/session revocation.

- [ ] **Step 4: Verify the deployment artifact**

Run: `docker compose -f deploy/compose.yaml config && docker build -f deploy/Dockerfile -t opswarden:test .`

Expected: both commands succeed; image history and inspection contain no key material; container runs as non-root; only Caddy publishes a host port.

- [ ] **Step 5: Commit**

```bash
git add deploy docs/operations.md docs/security-model.md .gitignore
git commit -m "ops: add hardened single-host deployment"
```

## Task 17: Add End-to-End, Security, and Restore Verification

**Files:**
- Create: `tests/e2e/playwright.config.ts`
- Create: `tests/e2e/package.json`
- Create: `tests/e2e/credential-agent.spec.ts`
- Create: `tests/e2e/permissions.spec.ts`
- Create: `tests/e2e/backup-restore.spec.ts`
- Create: `scripts/scan-sensitive-fixtures.sh`
- Create: `Makefile`
- Modify: `docs/operations.md`

**Interfaces:**
- Consumes: the complete Compose deployment.
- Produces: one-command verification through `make verify`.

- [ ] **Step 1: Write failing acceptance scenarios**

```ts
test("member and Hermes-style Agent share one credential lifecycle", async ({ page, request }) => {
  const h = await E2EHarness.start(page, request);
  const id = await h.createCredentialInUI({ displayName: "e2e-login", password: h.fixtures.password });
  expect(await h.mcpCredentialGet(id)).toMatchObject({ displayName: "e2e-login" });
  const version = await h.mcpCredentialUpdate(id, { displayName: "e2e-login-updated" });
  await h.mcpCredentialDelete(id, version);
  await expect(h.recycleBinRow(id)).toBeVisible();
  expect(await h.auditActionsFor(id)).toEqual(["credential.create", "credential.read", "credential.update", "credential.delete"]);
});

test("cross-Space IDs remain indistinguishable", async ({ request }) => {
  const h = await APIHarness.start(request);
  const missing = await h.getCredential("00000000-0000-0000-0000-000000000000");
  const forbidden = await h.getCredential(h.otherSpaceCredentialID);
  expect(forbidden.status()).toBe(missing.status());
  expect(await forbidden.json()).toMatchObject(await missing.json());
});
```

The restore scenario must create a known fixture, run an online backup, start a clean isolated Compose project with the backup and separate key, verify decryption, then revoke sessions and Agent Tokens created in the restored environment.

- [ ] **Step 2: Verify the acceptance suite fails before harness wiring**

Run: `cd tests/e2e && npm install && npx playwright test`

Expected: failure because no test deployment fixture is configured.

- [ ] **Step 3: Add deterministic verification commands**

```make
verify:
	go test -race ./...
	cd web && npm test -- --run && npm run build
	docker compose -f deploy/compose.yaml config
	docker build -f deploy/Dockerfile -t opswarden:test .
	cd tests/e2e && npx playwright test
	./scripts/scan-sensitive-fixtures.sh
```

The fixture scanner must search the SQLite file, online backup, application logs, audit export, browser storage dump, and captured HTTP/MCP error bodies for unique test passwords, Tokens, private keys, connection strings, TOTP seeds, session IDs, and the master key.

- [ ] **Step 4: Run the full release gate**

Run: `make verify`

Expected: all Go, React, REST, MCP, Playwright, Compose, container, restore, and sensitive-fixture checks pass with exit code 0.

- [ ] **Step 5: Commit**

```bash
git add tests scripts Makefile docs/operations.md
git commit -m "test: add end-to-end security and restore verification"
```

## Task 18: Final Spec Conformance Review

**Files:**
- Modify only files required by demonstrated conformance gaps.
- Review: `docs/superpowers/specs/2026-07-28-opswarden-design.md`
- Review: all production and test files.

**Interfaces:**
- Consumes: all preceding task outputs.
- Produces: a traceable release checklist with no unverified design claims.

- [ ] **Step 1: Map every acceptance criterion to evidence**

Create a temporary checklist from spec section 20 and attach one passing test name or exact manual verification command to each of the eleven criteria. Do not mark a criterion complete based only on code inspection when an executable check is possible.

- [ ] **Step 2: Run formatting, static analysis, dependency, and test gates**

Run: `gofmt -w cmd internal && go vet ./... && go test -race ./... && cd web && npm test -- --run && npm run build`

Expected: no formatting diff after the first run, no vet findings, and all tests/builds pass.

- [ ] **Step 3: Run deployment and acceptance gates from a clean checkout**

Run: `make verify`

Expected: exit code 0 from a clean checkout with only documented environment inputs.

- [ ] **Step 4: Inspect the final diff and runtime exposure**

Run: `git status --short && git diff --check && docker compose -f deploy/compose.yaml config`

Expected: if no fixes were needed, the worktree is clean; otherwise the diff contains only demonstrated conformance corrections. In both cases there are no whitespace errors, unexpected published ports, unpinned local paths, or sensitive files tracked by Git.

- [ ] **Step 5: Commit only if the conformance review required fixes**

```bash
git add -A
git commit -m "fix: close OpsWarden v1 conformance gaps"
```

If no files changed, record the passing commands in the task handoff and do not create an empty commit.
