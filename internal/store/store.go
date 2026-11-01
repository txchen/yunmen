// Package store owns all persistent state in one SQLite database.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/txchen/yunmen/internal/secrets"
	_ "modernc.org/sqlite"
)

type Store struct {
	db  *sql.DB
	Key *secrets.MasterKey
	now func() time.Time
}

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

// migrations are append-only. Never edit an applied migration.
var migrations = []string{
	`CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
	CREATE TABLE owner (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		password_hash TEXT NOT NULL,
		totp_secret BLOB NOT NULL,
		totp_last_step INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL
	);
	CREATE TABLE web_sessions (
		id TEXT PRIMARY KEY,
		token_hash BLOB NOT NULL UNIQUE,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		revoked_at INTEGER
	);
	CREATE TABLE devices (
		id TEXT PRIMARY KEY,
		label TEXT NOT NULL,
		token_hash BLOB NOT NULL UNIQUE,
		service_principal TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		last_used_at INTEGER,
		revoked_at INTEGER
	);
	CREATE TABLE hosts (
		id TEXT PRIMARY KEY,
		alias TEXT NOT NULL UNIQUE,
		name TEXT NOT NULL,
		address TEXT NOT NULL,
		port INTEGER NOT NULL,
		username TEXT NOT NULL,
		auth_kind TEXT NOT NULL CHECK (auth_kind IN ('key', 'password')),
		credential_id TEXT NOT NULL,
		credential BLOB NOT NULL,
		key_fingerprint TEXT NOT NULL DEFAULT '',
		host_key BLOB NOT NULL,
		revision INTEGER NOT NULL,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE uploads (
		id TEXT PRIMARY KEY,
		host_id TEXT NOT NULL,
		temp_path TEXT NOT NULL,
		created_at INTEGER NOT NULL
	);`,
}

const metaKeyCheck = "master_key_check"

// Open opens (creating if needed) the database, applies migrations and binds
// the master key. A fresh database records a key check; an existing one must
// match it. Nothing is written when the key check fails.
func Open(ctx context.Context, path string, key *secrets.MasterKey) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, Key: key, now: time.Now}
	if err := s.checkKeyBeforeMigrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.bindKey(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// SetClock replaces the time source; tests use it to exercise expiry.
func (s *Store) SetClock(now func() time.Time) { s.now = now }

func (s *Store) Now() time.Time { return s.now() }

func (s *Store) checkKeyBeforeMigrate(ctx context.Context) error {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='meta'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	var blob []byte
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key=?`, metaKeyCheck).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.Key.VerifyKeyCheck(blob)
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	var current int
	if err := s.db.QueryRowContext(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}
	if current > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this build (%d); refusing to start", current, len(migrations))
	}
	for v := current + 1; v <= len(migrations); v++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[v-1]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", v, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, v, s.now().Unix()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) bindKey(ctx context.Context) error {
	var blob []byte
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key=?`, metaKeyCheck).Scan(&blob)
	if err == nil {
		return s.Key.VerifyKeyCheck(blob)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// No key check yet. Refuse if any encrypted data exists: that data was
	// written under an unknown key and must not be adopted by a new one.
	var encrypted int
	if err := s.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM owner) + (SELECT count(*) FROM hosts)`).Scan(&encrypted); err != nil {
		return err
	}
	if encrypted > 0 {
		return errors.New("database has encrypted records but no master key check; refusing to adopt the configured key")
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES (?, ?)`, metaKeyCheck, s.Key.NewKeyCheck())
	return err
}

func unix(t time.Time) int64 { return t.Unix() }

func fromUnix(v int64) time.Time { return time.Unix(v, 0).UTC() }

func nullTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromUnix(v.Int64)
	return &t
}
