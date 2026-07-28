package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
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
	if before != 1 || after != before {
		t.Fatalf("migration counts before/after = %d/%d, want 1/1", before, after)
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
		(id, credential_id, version, encrypted_payload) VALUES ('cv1', 'c1', 1, X'01')`)
	if _, err := db.Writer.Exec(`INSERT INTO credential_versions
		(id, credential_id, version, encrypted_payload) VALUES ('cv2', 'c1', 1, X'02')`); err == nil {
		t.Fatal("duplicate credential version succeeded")
	}
	if _, err := db.Writer.Exec(`UPDATE credential_versions SET version = 2 WHERE id = 'cv1'`); err == nil {
		t.Fatal("credential version number update succeeded")
	}
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

	for _, index := range []string{
		"idx_assets_space_type", "idx_asset_tags_tag", "idx_credentials_space_type",
		"idx_credential_tags_tag", "idx_audit_events_space_created",
		"idx_sessions_expires", "idx_agent_tokens_expires",
		"idx_idempotency_records_expires",
	} {
		assertIndexExists(t, db.Writer, index)
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

func mustExec(t *testing.T, db *sql.DB, query string) {
	t.Helper()
	if _, err := db.Exec(query); err != nil {
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
