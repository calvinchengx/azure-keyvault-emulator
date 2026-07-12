// Package store is the persistence layer: pure-Go SQLite, one database for
// vaults, secret versions, and soft-deleted objects. All timestamps flow
// through Now (the controllable clock) so attribute windows and purge
// deadlines are deterministic.
package store

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/calvinchengx/azure-keyvault-emulator/internal/clock"
	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a name is unusable (e.g. soft-deleted).
var ErrConflict = errors.New("conflict")

// Store wraps the database plus the emulator clock.
type Store struct {
	db    *sql.DB
	Clock *clock.Clock
}

// Open opens (creating if needed) the database in dataDir; empty = in-memory.
func Open(dataDir string, ck *clock.Clock) (*Store, error) {
	dsn := ":memory:"
	if dataDir != "" {
		dsn = filepath.Join(dataDir, "azure-keyvault-emulator.db")
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, Clock: ck}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Now returns the current emulator time (epoch seconds).
func (s *Store) Now() int64 { return s.Clock.Now() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS secret_versions (
	vault TEXT NOT NULL,
	name TEXT NOT NULL,
	version TEXT NOT NULL,
	value TEXT NOT NULL,
	content_type TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1,
	nbf INTEGER,          -- NULL = unset
	exp INTEGER,          -- NULL = unset
	tags_json TEXT NOT NULL DEFAULT '{}',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (vault, name, version)
);
CREATE TABLE IF NOT EXISTS deleted_secrets (
	vault TEXT NOT NULL,
	name TEXT NOT NULL,
	deleted_at INTEGER NOT NULL,
	purge_at INTEGER NOT NULL,
	PRIMARY KEY (vault, name)
);
CREATE TABLE IF NOT EXISTS key_versions (
	vault TEXT NOT NULL,
	name TEXT NOT NULL,
	version TEXT NOT NULL,
	kty TEXT NOT NULL,              -- RSA | EC
	crv TEXT NOT NULL DEFAULT '',   -- EC curve name
	private_der TEXT NOT NULL,      -- base64(PKCS#8), never leaves the store
	key_ops_json TEXT NOT NULL DEFAULT '[]',
	enabled INTEGER NOT NULL DEFAULT 1,
	nbf INTEGER,
	exp INTEGER,
	tags_json TEXT NOT NULL DEFAULT '{}',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (vault, name, version)
);
CREATE TABLE IF NOT EXISTS deleted_keys (
	vault TEXT NOT NULL,
	name TEXT NOT NULL,
	deleted_at INTEGER NOT NULL,
	purge_at INTEGER NOT NULL,
	PRIMARY KEY (vault, name)
);
CREATE TABLE IF NOT EXISTS cert_versions (
	vault TEXT NOT NULL,
	name TEXT NOT NULL,
	version TEXT NOT NULL,
	cer_der TEXT NOT NULL,          -- base64(DER) of the X.509 cert
	private_der TEXT NOT NULL,      -- base64(PKCS#8) private key, never returned
	policy_json TEXT NOT NULL DEFAULT '{}',
	thumbprint TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1,
	nbf INTEGER,
	exp INTEGER,
	tags_json TEXT NOT NULL DEFAULT '{}',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (vault, name, version)
);
CREATE TABLE IF NOT EXISTS deleted_certs (
	vault TEXT NOT NULL,
	name TEXT NOT NULL,
	deleted_at INTEGER NOT NULL,
	purge_at INTEGER NOT NULL,
	PRIMARY KEY (vault, name)
);
`)
	return err
}

// NewVersionID returns a 32-hex version id, the format real Key Vault uses.
func NewVersionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return fmt.Sprintf("%x", b)
}
