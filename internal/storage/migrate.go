package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
)

//go:embed migrations/*.sql
var migrations embed.FS

var migrationNamePattern = regexp.MustCompile(`^([0-9]{4})_[a-z0-9][a-z0-9_]*\.sql$`)

type migration struct {
	version  int
	name     string
	contents []byte
	checksum string
}

func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("database is required")
	}
	available, err := loadMigrations(migrations)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			checksum TEXT NOT NULL CHECK (length(checksum) = 64),
			applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("create schema migrations table: %w", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve migration connection: %w", err)
	}
	defer conn.Close()

	return withImmediateTransaction(ctx, conn, func() error {
		applied, err := validateAppliedMigrations(ctx, conn, available)
		if err != nil {
			return err
		}
		for _, migration := range available {
			if applied[migration.version] {
				continue
			}
			if _, err := conn.ExecContext(ctx, string(migration.contents)); err != nil {
				return fmt.Errorf("apply migration %s: %w", migration.name, err)
			}
			if _, err := conn.ExecContext(ctx, `
				INSERT INTO schema_migrations (version, name, checksum)
				VALUES (?, ?, ?)
			`, migration.version, migration.name, migration.checksum); err != nil {
				return fmt.Errorf("record migration %s: %w", migration.name, err)
			}
		}
		return nil
	})
}

func loadMigrations(fsys fs.FS) ([]migration, error) {
	names, err := fs.Glob(fsys, "migrations/*.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	available := make([]migration, 0, len(names))
	versions := make(map[int]string, len(names))
	for _, migrationPath := range names {
		name := path.Base(migrationPath)
		matches := migrationNamePattern.FindStringSubmatch(name)
		if matches == nil {
			return nil, fmt.Errorf("invalid migration filename %q", name)
		}
		version, err := strconv.Atoi(matches[1])
		if err != nil || version == 0 {
			return nil, fmt.Errorf("invalid migration version in %q", name)
		}
		if previous, exists := versions[version]; exists {
			return nil, fmt.Errorf("duplicate migration version %04d in %q and %q", version, previous, name)
		}
		contents, err := fs.ReadFile(fsys, migrationPath)
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", name, err)
		}
		sum := sha256.Sum256(contents)
		available = append(available, migration{
			version:  version,
			name:     name,
			contents: contents,
			checksum: fmt.Sprintf("%x", sum),
		})
		versions[version] = name
	}
	sort.Slice(available, func(i, j int) bool {
		return available[i].version < available[j].version
	})
	return available, nil
}

func withImmediateTransaction(ctx context.Context, conn *sql.Conn, fn func() error) (err error) {
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("begin immediate migration transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if _, rollbackErr := conn.ExecContext(context.Background(), `ROLLBACK`); rollbackErr != nil {
			rollbackErr = fmt.Errorf("rollback migration transaction: %w", rollbackErr)
			err = errors.Join(err, rollbackErr)
		}
	}()

	if err = fn(); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("commit migration transaction: %w", err)
	}
	committed = true
	return nil
}

func validateAppliedMigrations(
	ctx context.Context,
	conn *sql.Conn,
	available []migration,
) (map[int]bool, error) {
	known := make(map[int]migration, len(available))
	maxVersion := 0
	for _, migration := range available {
		known[migration.version] = migration
		if migration.version > maxVersion {
			maxVersion = migration.version
		}
	}

	rows, err := conn.QueryContext(ctx, `
		SELECT version, name, checksum
		FROM schema_migrations
		ORDER BY version
	`)
	if err != nil {
		return nil, fmt.Errorf("read applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var version int
		var name, checksum string
		if err := rows.Scan(&version, &name, &checksum); err != nil {
			return nil, fmt.Errorf("scan applied migration: %w", err)
		}
		expected, exists := known[version]
		if !exists {
			if version > maxVersion {
				return nil, fmt.Errorf(
					"database migration version %04d is newer than supported version %04d",
					version,
					maxVersion,
				)
			}
			return nil, fmt.Errorf("database contains unknown migration version %04d", version)
		}
		if name != expected.name {
			return nil, fmt.Errorf(
				"migration version %04d name mismatch: database has %q, binary has %q",
				version,
				name,
				expected.name,
			)
		}
		if checksum != expected.checksum {
			return nil, fmt.Errorf("migration %s checksum mismatch", expected.name)
		}
		applied[version] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read applied migrations: %w", err)
	}
	return applied, nil
}
