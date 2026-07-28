package storage

import (
	"context"
	"database/sql"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

func TestInitialMigrationCreatesAllTables(t *testing.T) {
	db := openTempDB(t)

	for _, table := range []string{
		"users", "user_totp", "recovery_codes", "sessions", "spaces",
		"space_memberships", "agents", "agent_tokens", "agent_space_grants",
		"assets", "asset_tags", "credentials", "credential_versions",
		"credential_tags", "asset_credentials", "audit_events",
		"idempotency_records", "backup_runs",
	} {
		assertTableExists(t, db.Writer, table)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	db := openTempDB(t)

	var before int
	if err := db.Writer.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(context.Background(), db.Writer); err != nil {
		t.Fatal(err)
	}
	var after int
	if err := db.Writer.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != 2 || after != before {
		t.Fatalf("migration counts before/after = %d/%d, want 2/2", before, after)
	}
}

func TestConcurrentMigrateOnIndependentDatabases(t *testing.T) {
	for iteration := range 10 {
		t.Run(string(rune('A'+iteration)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "concurrent.db")
			databases := make([]*sql.DB, 2)
			for i := range databases {
				db, err := sql.Open(driverName, sqliteDSN(path))
				if err != nil {
					t.Fatal(err)
				}
				db.SetMaxOpenConns(1)
				databases[i] = db
				t.Cleanup(func() { _ = db.Close() })
				if err := db.Ping(); err != nil {
					t.Fatal(err)
				}
			}

			start := make(chan struct{})
			errs := make(chan error, len(databases))
			var ready sync.WaitGroup
			ready.Add(len(databases))
			for _, db := range databases {
				go func() {
					ready.Done()
					<-start
					errs <- Migrate(context.Background(), db)
				}()
			}
			ready.Wait()
			close(start)

			for range databases {
				if err := <-errs; err != nil {
					t.Fatalf("concurrent Migrate: %v", err)
				}
			}

			var versions int
			if err := databases[0].QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&versions); err != nil {
				t.Fatal(err)
			}
			if versions != 2 {
				t.Fatalf("schema migration count = %d, want 2", versions)
			}
		})
	}
}

func TestImmediateMigrationTransactionLocksBeforeCallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock.db")
	firstDB, err := sql.Open(driverName, sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer firstDB.Close()
	secondDB, err := sql.Open(driverName, sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer secondDB.Close()

	ctx := context.Background()
	firstConn, err := firstDB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer firstConn.Close()
	secondConn, err := secondDB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer secondConn.Close()
	if _, err := secondConn.ExecContext(ctx, `PRAGMA busy_timeout = 25`); err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	firstErr := make(chan error, 1)
	go func() {
		firstErr <- withImmediateTransaction(ctx, firstConn, func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	secondCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	secondCallbackCalled := false
	err = withImmediateTransaction(secondCtx, secondConn, func() error {
		secondCallbackCalled = true
		return nil
	})
	if err == nil {
		t.Fatal("second immediate transaction acquired the migration lock")
	}
	if secondCallbackCalled {
		t.Fatal("second callback ran without acquiring the migration lock")
	}

	close(release)
	if err := <-firstErr; err != nil {
		t.Fatalf("first immediate transaction: %v", err)
	}
}

func TestMigrateRollsBackFailedMigrationAndVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollback.db")
	db, err := sql.Open(driverName, sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// This table is deliberately last in the initial migration. Its presence
	// makes that migration fail after earlier DDL has run.
	if _, err := db.Exec(`CREATE TABLE backup_runs (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(context.Background(), db); err == nil {
		t.Fatal("Migrate succeeded, want an error")
	}

	assertTableMissing(t, db, "users")
	var versions int
	if err := db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 0 {
		t.Fatalf("schema migration count = %d, want 0", versions)
	}
}

func TestInitialSchemaEnforcesRequiredIntegrity(t *testing.T) {
	db := openTempDB(t)

	mustExec(t, db.Writer, `INSERT INTO users (id, email, normalized_email, password_hash)
		VALUES ('u1', 'Admin@Example.com', 'admin@example.com', X'01')`)
	if _, err := db.Writer.Exec(`INSERT INTO users (id, email, normalized_email, password_hash)
		VALUES ('u2', 'ADMIN@example.com', 'admin@example.com', X'02')`); err == nil {
		t.Fatal("duplicate normalized email succeeded")
	}

	mustExec(t, db.Writer, `INSERT INTO spaces (id, name) VALUES ('s1', 'One'), ('s2', 'Two')`)
	mustExec(t, db.Writer, `INSERT INTO assets (id, space_id, name, type) VALUES ('a1', 's1', 'Host', 'server')`)
	mustExec(t, db.Writer, `INSERT INTO credentials (id, space_id, name, type) VALUES ('c1', 's2', 'SSH', 'ssh')`)
	if _, err := db.Writer.Exec(`INSERT INTO asset_credentials (space_id, asset_id, credential_id)
		VALUES ('s1', 'a1', 'c1')`); err == nil {
		t.Fatal("cross-space asset credential link succeeded")
	}

	mustExec(t, db.Writer, `INSERT INTO credential_versions
		(id, credential_id, version, payload_ciphertext, payload_nonce, wrapped_data_key, wrap_nonce)
		VALUES ('cv1', 'c1', 1, zeroblob(16), zeroblob(24), zeroblob(48), zeroblob(24))`)
	if _, err := db.Writer.Exec(`INSERT INTO credential_versions
		(id, credential_id, version, payload_ciphertext, payload_nonce, wrapped_data_key, wrap_nonce)
		VALUES ('cv2', 'c1', 1, zeroblob(16), zeroblob(24), zeroblob(48), zeroblob(24))`); err == nil {
		t.Fatal("duplicate credential version succeeded")
	}
	if _, err := db.Writer.Exec(`UPDATE credential_versions SET version = 2 WHERE id = 'cv1'`); err == nil {
		t.Fatal("credential version number update succeeded")
	}
	for name, statement := range map[string]string{
		"ciphertext": `UPDATE credential_versions SET payload_ciphertext = X'01' WHERE id = 'cv1'`,
		"creator":    `UPDATE credential_versions SET created_by_user_id = NULL WHERE id = 'cv1'`,
		"time":       `UPDATE credential_versions SET created_at = CURRENT_TIMESTAMP WHERE id = 'cv1'`,
	} {
		t.Run("immutable_"+name, func(t *testing.T) {
			if _, err := db.Writer.Exec(statement); err == nil {
				t.Fatalf("credential version %s update succeeded", name)
			}
		})
	}
	if _, err := db.Writer.Exec(`DELETE FROM credential_versions WHERE id = 'cv1'`); err != nil {
		t.Fatalf("delete immutable credential version: %v", err)
	}
}

func TestIdentityStateMigrationAddsRoleReplayAndSessionExpiryColumns(t *testing.T) {
	db := openTempDB(t)

	mustExec(t, db.Writer, `INSERT INTO users
		(id, email, normalized_email, password_hash, system_role)
		VALUES ('identity-user', 'owner@example.com', 'owner@example.com', X'01', 'system_owner')`)
	if _, err := db.Writer.Exec(`INSERT INTO users
		(id, email, normalized_email, password_hash, system_role)
		VALUES ('bad-role', 'bad@example.com', 'bad@example.com', X'01', 'invalid')`); err == nil {
		t.Fatal("invalid system role succeeded")
	}

	mustExec(t, db.Writer, `INSERT INTO user_totp
		(user_id, encrypted_secret, last_used_counter)
		VALUES ('identity-user', X'01', 42)`)
	if _, err := db.Writer.Exec(`UPDATE user_totp SET last_used_counter = -1
		WHERE user_id = 'identity-user'`); err == nil {
		t.Fatal("negative TOTP counter succeeded")
	}

	mustExec(t, db.Writer, `INSERT INTO sessions
		(id, user_id, token_hash, expires_at, idle_expires_at, recent_totp_at)
		VALUES ('identity-session', 'identity-user', X'02',
			'2026-07-29T09:30:00Z', '2026-07-28T17:30:00Z', '2026-07-28T09:30:00Z')`)
}

func TestInitialSchemaContainsHashSoftDeleteAndLookupColumns(t *testing.T) {
	db := openTempDB(t)

	assertColumns(t, db.Writer, "sessions", "token_hash", "expires_at")
	assertColumns(t, db.Writer, "agent_tokens", "token_hash", "expires_at")
	assertColumns(t, db.Writer, "users", "deleted_at")
	assertColumns(t, db.Writer, "assets", "deleted_at")
	assertColumns(t, db.Writer, "credentials", "deleted_at")
	assertColumns(t, db.Writer, "idempotency_records", "agent_id", "endpoint", "key_hash", "expires_at")
	assertColumns(t, db.Writer, "asset_tags", "asset_id", "tag")
	assertColumns(t, db.Writer, "credential_tags", "credential_id", "tag")
	assertColumns(t, db.Writer, "credentials", "current_version")
	assertColumns(t, db.Writer, "credential_versions",
		"payload_ciphertext", "payload_nonce", "wrapped_data_key", "wrap_nonce")
	assertColumnMissing(t, db.Writer, "credential_versions", "encrypted_payload")

	for _, index := range []string{
		"idx_assets_space_type", "idx_asset_tags_tag", "idx_credentials_space_type",
		"idx_credential_tags_tag", "idx_audit_events_space_created",
		"idx_sessions_expires", "idx_agent_tokens_expires",
		"idx_idempotency_records_expires",
	} {
		assertIndexExists(t, db.Writer, index)
	}
}

func TestCredentialVersionEnvelopeLengthChecks(t *testing.T) {
	db := openTempDB(t)
	mustExec(t, db.Writer, `INSERT INTO spaces (id, name) VALUES ('s1', 'One')`)
	mustExec(t, db.Writer, `INSERT INTO credentials (id, space_id, name, type)
		VALUES ('c1', 's1', 'SSH', 'ssh')`)

	tests := map[string]string{
		"short payload ciphertext": `zeroblob(15), zeroblob(24), zeroblob(48), zeroblob(24)`,
		"payload nonce":            `zeroblob(16), zeroblob(23), zeroblob(48), zeroblob(24)`,
		"wrapped data key":         `zeroblob(16), zeroblob(24), zeroblob(47), zeroblob(24)`,
		"wrap nonce":               `zeroblob(16), zeroblob(24), zeroblob(48), zeroblob(25)`,
	}
	version := 0
	for name, values := range tests {
		version++
		t.Run(name, func(t *testing.T) {
			_, err := db.Writer.Exec(`INSERT INTO credential_versions
				(id, credential_id, version, payload_ciphertext, payload_nonce, wrapped_data_key, wrap_nonce)
				VALUES (?, 'c1', ?, `+values+`)`, name, version)
			if err == nil {
				t.Fatal("invalid envelope lengths succeeded")
			}
		})
	}
}

func TestLoadMigrationsRejectsInvalidNamesAndDuplicateVersions(t *testing.T) {
	for name, migrationFS := range map[string]fs.FS{
		"missing number": fstest.MapFS{
			"migrations/initial.sql": &fstest.MapFile{Data: []byte(`SELECT 1;`)},
		},
		"short number": fstest.MapFS{
			"migrations/01_initial.sql": &fstest.MapFile{Data: []byte(`SELECT 1;`)},
		},
		"duplicate version": fstest.MapFS{
			"migrations/0001_one.sql": &fstest.MapFile{Data: []byte(`SELECT 1;`)},
			"migrations/0001_two.sql": &fstest.MapFile{Data: []byte(`SELECT 2;`)},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadMigrations(migrationFS); err == nil {
				t.Fatal("loadMigrations succeeded")
			}
		})
	}
}

func TestMigrateRejectsChecksumMismatch(t *testing.T) {
	db := openTempDB(t)
	mustExec(t, db.Writer, `UPDATE schema_migrations SET checksum = ?`, strings.Repeat("0", 64))

	if err := Migrate(context.Background(), db.Writer); err == nil {
		t.Fatal("Migrate succeeded with a changed applied migration")
	}
}

func TestMigrateRejectsUnknownHigherVersion(t *testing.T) {
	db := openTempDB(t)
	mustExec(t, db.Writer, `INSERT INTO schema_migrations (version, name, checksum)
		VALUES (9999, '9999_future.sql', ?)`, strings.Repeat("0", 64))

	if err := Migrate(context.Background(), db.Writer); err == nil {
		t.Fatal("Migrate succeeded with an unknown higher version")
	}
}

func assertTableExists(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("table %q count = %d, want 1", table, count)
	}
}

func assertTableMissing(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("table %q exists after failed migration", table)
	}
}

func assertColumns(t *testing.T, db *sql.DB, table string, want ...string) {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	have := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, column := range want {
		if !have[column] {
			t.Errorf("table %q missing column %q; has %s", table, column, strings.Join(mapKeys(have), ", "))
		}
	}
}

func assertColumnMissing(t *testing.T, db *sql.DB, table, unwanted string) {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		if name == unwanted {
			t.Fatalf("table %q unexpectedly contains column %q", table, unwanted)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func assertIndexExists(t *testing.T, db *sql.DB, index string) {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE type = 'index' AND name = ?`, index).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("index %q count = %d, want 1", index, count)
	}
}

func mustExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func mapKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
