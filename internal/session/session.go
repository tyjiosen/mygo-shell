// Package session stores connection profiles in SQLite and keeps their
// passwords encrypted with package vault.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/egoist/mygo/plugins/sqlite"

	"github.com/tyjiosen/mygo-shell/internal/vault"
)

// Protocol is how a session reaches its target.
type Protocol string

const (
	ProtocolSSH    Protocol = "ssh"
	ProtocolTelnet Protocol = "telnet"
	ProtocolSerial Protocol = "serial"
	ProtocolLocal  Protocol = "local"
)

// AuthMethod is how a session authenticates.
const (
	AuthPassword = "password"
	AuthKey      = "key"
	AuthAgent    = "agent"
)

// Session is one saved connection profile. Password is only read when it is
// given to Save; loaded sessions report HasPassword instead.
type Session struct {
	ID         string
	Name       string
	Protocol   Protocol
	Host       string
	Port       int
	User       string
	AuthMethod string
	KeyPath    string
	TermType   string

	Password    string `json:"-"`
	HasPassword bool   `json:"has_password"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Store reads and writes sessions.
type Store struct {
	db     *sqlite.DB
	sealer *vault.Vault
}

const createSessions = `
CREATE TABLE IF NOT EXISTS sessions (
	id          TEXT PRIMARY KEY,
	name        TEXT NOT NULL,
	protocol    TEXT NOT NULL DEFAULT 'ssh',
	host        TEXT NOT NULL DEFAULT '',
	port        INTEGER NOT NULL DEFAULT 22,
	user        TEXT NOT NULL DEFAULT '',
	auth_method TEXT NOT NULL DEFAULT 'password',
	key_path    TEXT NOT NULL DEFAULT '',
	term_type   TEXT NOT NULL DEFAULT 'xterm-256color',
	secret      TEXT NOT NULL DEFAULT '',
	created_at  TEXT NOT NULL,
	updated_at  TEXT NOT NULL
);`

// Open connects to the database at dbPath, creating the schema when missing,
// and unlocks the vault whose key lives at keyPath.
func Open(ctx context.Context, dbPath, keyPath string) (*Store, error) {
	db, err := sqlite.Open(ctx, dbPath, sqlite.OpenOptions{})
	if err != nil {
		return nil, fmt.Errorf("session: open %s: %w", dbPath, err)
	}

	sealer, err := vault.Open(keyPath)
	if err != nil {
		db.Close()
		return nil, err
	}

	s := &Store{db: db, sealer: sealer}
	if _, err := db.Execute(ctx, createSessions); err != nil {
		db.Close()
		return nil, fmt.Errorf("session: create schema: %w", err)
	}
	return s, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// Save inserts or updates a session, encrypting Password when it is set.
func (s *Store) Save(ctx context.Context, item *Session) error {
	if item.Name == "" {
		return errors.New("session: name is required")
	}
	if item.Protocol == "" {
		item.Protocol = ProtocolSSH
	}
	if item.AuthMethod == "" {
		item.AuthMethod = AuthPassword
	}
	if item.TermType == "" {
		item.TermType = "xterm-256color"
	}

	now := time.Now().UTC()
	if item.ID == "" {
		item.ID = newID()
		item.CreatedAt = now
	}
	item.UpdatedAt = now
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}

	secret, err := s.sealer.Encrypt(item.Password)
	if err != nil {
		return err
	}

	// An empty password leaves the stored secret untouched, so saving a
	// profile from the UI does not wipe a password it did not ask for.
	const upsert = `
INSERT INTO sessions (id, name, protocol, host, port, user, auth_method, key_path, term_type, secret, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	name = excluded.name,
	protocol = excluded.protocol,
	host = excluded.host,
	port = excluded.port,
	user = excluded.user,
	auth_method = excluded.auth_method,
	key_path = excluded.key_path,
	term_type = excluded.term_type,
	secret = CASE WHEN excluded.secret = '' THEN sessions.secret ELSE excluded.secret END,
	updated_at = excluded.updated_at;`

	_, err = s.db.Execute(ctx, upsert,
		item.ID, item.Name, string(item.Protocol), item.Host, item.Port, item.User,
		item.AuthMethod, item.KeyPath, item.TermType, secret,
		item.CreatedAt.Format(time.RFC3339), item.UpdatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("session: save %q: %w", item.Name, err)
	}
	item.HasPassword = item.Password != "" || item.HasPassword
	return nil
}

// List returns every session ordered by name, without secrets.
func (s *Store) List(ctx context.Context) ([]Session, error) {
	const q = `
SELECT id, name, protocol, host, port, user, auth_method, key_path, term_type,
       secret <> '' AS has_password, created_at, updated_at
FROM sessions ORDER BY name COLLATE NOCASE;`

	rows, err := s.db.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("session: list: %w", err)
	}

	out := make([]Session, 0, len(rows.Values))
	for _, v := range rows.Values {
		out = append(out, sessionFromRow(v))
	}
	return out, nil
}

// Get returns one session by ID, without its secret.
func (s *Store) Get(ctx context.Context, id string) (Session, error) {
	const q = `
SELECT id, name, protocol, host, port, user, auth_method, key_path, term_type,
       secret <> '' AS has_password, created_at, updated_at
FROM sessions WHERE id = ?;`

	rows, err := s.db.Query(ctx, q, id)
	if err != nil {
		return Session{}, fmt.Errorf("session: get %s: %w", id, err)
	}
	if len(rows.Values) == 0 {
		return Session{}, fmt.Errorf("session: %s not found", id)
	}
	return sessionFromRow(rows.Values[0]), nil
}

// Password decrypts the stored password of a session.
func (s *Store) Password(ctx context.Context, id string) (string, error) {
	rows, err := s.db.Query(ctx, `SELECT secret FROM sessions WHERE id = ?;`, id)
	if err != nil {
		return "", fmt.Errorf("session: password %s: %w", id, err)
	}
	if len(rows.Values) == 0 {
		return "", fmt.Errorf("session: %s not found", id)
	}
	secret, _ := rows.Values[0][0].(string)
	return s.sealer.Decrypt(secret)
}

// Delete removes a session.
func (s *Store) Delete(ctx context.Context, id string) error {
	if _, err := s.db.Execute(ctx, `DELETE FROM sessions WHERE id = ?;`, id); err != nil {
		return fmt.Errorf("session: delete %s: %w", id, err)
	}
	return nil
}

// sessionFromRow maps a query row in the order used by List and Get.
func sessionFromRow(v []any) Session {
	item := Session{
		ID:         asString(v[0]),
		Name:       asString(v[1]),
		Protocol:   Protocol(asString(v[2])),
		Host:       asString(v[3]),
		Port:       asInt(v[4]),
		User:       asString(v[5]),
		AuthMethod: asString(v[6]),
		KeyPath:    asString(v[7]),
		TermType:   asString(v[8]),
		HasPassword: asInt(v[9]) != 0,
	}
	item.CreatedAt = asTime(v[10])
	item.UpdatedAt = asTime(v[11])
	return item
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asInt(v any) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}

func asTime(v any) time.Time {
	t, err := time.Parse(time.RFC3339, asString(v))
	if err != nil {
		return time.Time{}
	}
	return t
}

// newID returns a random 32 character identifier.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
