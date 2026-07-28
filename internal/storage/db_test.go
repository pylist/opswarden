package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenEnablesRequiredPragmasOnEveryConnection(t *testing.T) {
	db := openTempDB(t)

	assertPragmasOnConnections(t, db.Writer, 1, "0")
	assertPragmasOnConnections(t, db.Reader, 4, "1")
}

func TestOpenConfiguresWriterAndReaderPools(t *testing.T) {
	db := openTempDB(t)

	if got := db.Writer.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("writer MaxOpenConnections = %d, want 1", got)
	}
	if got := db.Reader.Stats().MaxOpenConnections; got != 4 {
		t.Fatalf("reader MaxOpenConnections = %d, want 4", got)
	}

	if _, err := db.Writer.Exec(`INSERT INTO spaces (id, name) VALUES ('space-1', 'Operations')`); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := db.Reader.QueryRow(`SELECT name FROM spaces WHERE id = 'space-1'`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "Operations" {
		t.Fatalf("space name = %q, want Operations", name)
	}
}

func TestReaderRejectsWritesWhileWriterAcceptsThem(t *testing.T) {
	db := openTempDB(t)

	if _, err := db.Writer.Exec(`INSERT INTO spaces (id, name) VALUES ('writer-space', 'Writer')`); err != nil {
		t.Fatalf("writer insert: %v", err)
	}
	if _, err := db.Reader.Exec(`INSERT INTO spaces (id, name) VALUES ('reader-space', 'Reader')`); err == nil {
		t.Fatal("reader insert succeeded")
	}
	if _, err := db.Reader.Exec(`UPDATE spaces SET name = 'Changed' WHERE id = 'writer-space'`); err == nil {
		t.Fatal("reader update succeeded")
	}

	var name string
	if err := db.Reader.QueryRow(`SELECT name FROM spaces WHERE id = 'writer-space'`).Scan(&name); err != nil {
		t.Fatalf("reader select: %v", err)
	}
	if name != "Writer" {
		t.Fatalf("space name = %q, want Writer", name)
	}
}

func TestWithTxCommitsAndRollsBackUsingWriter(t *testing.T) {
	db := openTempDB(t)
	ctx := context.Background()

	if err := WithTx(ctx, db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO spaces (id, name) VALUES ('committed', 'Committed')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("roll back")
	err := WithTx(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO spaces (id, name) VALUES ('rolled-back', 'Rolled Back')`); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("WithTx error = %v, want %v", err, sentinel)
	}

	var count int
	if err := db.Writer.QueryRow(`SELECT count(*) FROM spaces WHERE id = 'committed'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("committed row count = %d, want 1", count)
	}
	if err := db.Writer.QueryRow(`SELECT count(*) FROM spaces WHERE id = 'rolled-back'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rolled-back row count = %d, want 0", count)
	}
}

func TestWithTxRollsBackPanicAndReleasesWriter(t *testing.T) {
	db := openTempDB(t)
	ctx := context.Background()
	sentinel := errors.New("panic sentinel")

	var recovered any
	func() {
		defer func() {
			recovered = recover()
		}()
		_ = WithTx(ctx, db, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO spaces (id, name) VALUES ('panic', 'Panic')`); err != nil {
				t.Fatal(err)
			}
			panic(sentinel)
		})
	}()
	if recovered != sentinel {
		t.Fatalf("recovered panic = %v, want %v", recovered, sentinel)
	}

	txCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := WithTx(txCtx, db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(txCtx, `INSERT INTO spaces (id, name) VALUES ('after-panic', 'After Panic')`)
		return err
	}); err != nil {
		t.Fatalf("writer remained occupied after panic: %v", err)
	}

	var count int
	if err := db.Writer.QueryRow(`SELECT count(*) FROM spaces WHERE id = 'panic'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("panicking transaction row count = %d, want 0", count)
	}
}

func TestWithTxDoesNotUseReaderPool(t *testing.T) {
	db := openTempDB(t)
	ctx := context.Background()

	readerConnections := make([]*sql.Conn, 0, 4)
	for range 4 {
		conn, err := db.Reader.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		readerConnections = append(readerConnections, conn)
	}
	defer func() {
		for _, conn := range readerConnections {
			if err := conn.Close(); err != nil {
				t.Errorf("close reader connection: %v", err)
			}
		}
	}()

	txCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := WithTx(txCtx, db, func(*sql.Tx) error { return nil }); err != nil {
		t.Fatalf("WithTx blocked on the saturated reader pool: %v", err)
	}
}

func openTempDB(t *testing.T) *DB {
	t.Helper()

	path := filepath.Join(t.TempDir(), "nested", "opswarden.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	return db
}

func assertPragmasOnConnections(t *testing.T, pool *sql.DB, count int, wantQueryOnly string) {
	t.Helper()
	ctx := context.Background()
	conns := make([]*sql.Conn, 0, count)
	for range count {
		conn, err := pool.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
	}
	defer func() {
		for _, conn := range conns {
			if err := conn.Close(); err != nil {
				t.Errorf("close connection: %v", err)
			}
		}
	}()

	for i, conn := range conns {
		t.Run(fmt.Sprintf("connection_%d", i+1), func(t *testing.T) {
			assertPragma(t, conn, "journal_mode", "wal")
			assertPragma(t, conn, "foreign_keys", "1")
			assertPragma(t, conn, "busy_timeout", "5000")
			assertPragma(t, conn, "query_only", wantQueryOnly)
		})
	}
}

func assertPragma(t *testing.T, db *sql.Conn, name, want string) {
	t.Helper()
	var got string
	if err := db.QueryRowContext(context.Background(), "PRAGMA "+name).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("PRAGMA %s = %q, want %q", name, got, want)
	}
}
