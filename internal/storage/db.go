package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

const driverName = "sqlite"

type DB struct {
	Writer *sql.DB
	Reader *sql.DB
}

func Open(path string) (_ *DB, err error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absolutePath), 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	dsn := sqliteDSN(absolutePath)
	writer, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("open writer: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, writer.Close())
		}
	}()
	writer.SetMaxOpenConns(1)
	writer.SetMaxIdleConns(1)

	if err := writer.Ping(); err != nil {
		return nil, fmt.Errorf("connect writer: %w", err)
	}
	if err := Migrate(context.Background(), writer); err != nil {
		return nil, fmt.Errorf("migrate database: %w", err)
	}

	reader, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("open reader: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, reader.Close())
		}
	}()
	reader.SetMaxOpenConns(4)
	reader.SetMaxIdleConns(4)
	if err := reader.Ping(); err != nil {
		return nil, fmt.Errorf("connect reader: %w", err)
	}

	return &DB{Writer: writer, Reader: reader}, nil
}

func (db *DB) Close() error {
	if db == nil {
		return nil
	}
	var errs []error
	if db.Reader != nil {
		errs = append(errs, db.Reader.Close())
	}
	if db.Writer != nil {
		errs = append(errs, db.Writer.Close())
	}
	return errors.Join(errs...)
}

func WithTx(ctx context.Context, db *DB, fn func(*sql.Tx) error) error {
	if db == nil || db.Writer == nil {
		return errors.New("writer database is required")
	}
	if fn == nil {
		return errors.New("transaction callback is required")
	}

	tx, err := db.Writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback transaction: %w", rollbackErr))
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

func sqliteDSN(path string) string {
	location := url.URL{Scheme: "file", Path: path}
	query := url.Values{}
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "foreign_keys(ON)")
	query.Add("_pragma", "busy_timeout(5000)")
	location.RawQuery = query.Encode()
	return location.String()
}
