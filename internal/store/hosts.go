package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/txchen/yunmen/internal/secrets"
)

type AuthKind string

const (
	AuthKey      AuthKind = "key"
	AuthPassword AuthKind = "password"
)

// Host is catalog metadata. It never carries the target credential.
type Host struct {
	ID             string    `json:"id"`
	Alias          string    `json:"alias"`
	Name           string    `json:"name"`
	Address        string    `json:"address"`
	Port           int       `json:"port"`
	Username       string    `json:"username"`
	AuthKind       AuthKind  `json:"authKind"`
	KeyID          string    `json:"keyId,omitempty"`
	KeyLabel       string    `json:"keyLabel,omitempty"`
	KeyFingerprint string    `json:"keyFingerprint,omitempty"`
	HostKey        []byte    `json:"-"`
	CredentialID   string    `json:"-"`
	Revision       int64     `json:"revision"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// Credential is a decrypted target credential. Exactly one field is set,
// matching Kind. It must never be serialized to clients.
type Credential struct {
	Kind       AuthKind
	KeyID      string // library key, for AuthKey; lets revocation find users of the key
	PrivateKey []byte // unencrypted OpenSSH PEM, normalized at import
	Password   string
}

// HostSpec is validated catalog input.
type HostSpec struct {
	Alias, Name, Address, Username string
	Port                           int
}

var aliasRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func ParseHostSpec(alias, name, address, username string, port int) (HostSpec, error) {
	alias = strings.TrimSpace(alias)
	name = strings.TrimSpace(name)
	address = strings.TrimSpace(address)
	username = strings.TrimSpace(username)
	switch {
	case !aliasRE.MatchString(alias):
		return HostSpec{}, errors.New("alias must be 1-63 characters: lowercase letters, digits, '.', '_' or '-'")
	case utf8.RuneCountInString(name) > 100:
		return HostSpec{}, errors.New("name must be at most 100 characters")
	case address == "" || len(address) > 253 || strings.ContainsAny(address, " /\\@\x00") || strings.HasPrefix(address, "-"):
		return HostSpec{}, errors.New("address must be a hostname or IP address")
	case port < 1 || port > 65535:
		return HostSpec{}, errors.New("port must be 1-65535")
	case username == "" || len(username) > 64 || strings.ContainsAny(username, " \x00@:") || strings.HasPrefix(username, "-"):
		return HostSpec{}, errors.New("username is invalid")
	}
	if strings.Contains(address, ":") && net.ParseIP(address) == nil {
		return HostSpec{}, errors.New("address must not include a port; use the port field")
	}
	if name == "" {
		name = alias
	}
	return HostSpec{Alias: alias, Name: name, Address: address, Username: username, Port: port}, nil
}

func (h HostSpec) Endpoint() string { return net.JoinHostPort(h.Address, fmt.Sprint(h.Port)) }

func (h Host) Endpoint() string { return net.JoinHostPort(h.Address, fmt.Sprint(h.Port)) }

func passwordAAD(hostID, credID string) string { return hostID + "/" + credID }

// HostAuth is how a host authenticates: a library key or a host-owned password.
type HostAuth struct {
	Kind     AuthKind
	KeyID    string // AuthKey
	Password string // AuthPassword
}

// authColumns returns the stored representation of auth for host id: the
// key reference, a fresh credential ID and the sealed password (empty for keys).
func (s *Store) authColumns(hostID string, a HostAuth) (keyID sql.NullString, credID string, blob []byte) {
	credID = NewID()
	if a.Kind == AuthKey {
		return sql.NullString{String: a.KeyID, Valid: true}, credID, []byte{}
	}
	return sql.NullString{}, credID, s.Key.Seal(secrets.PurposeTargetCred, passwordAAD(hostID, credID), []byte(a.Password))
}

const hostSelect = `SELECT h.id, h.alias, h.name, h.address, h.port, h.username, h.auth_kind, h.credential_id,
	coalesce(h.key_id, ''), coalesce(k.label, ''), coalesce(k.fingerprint, ''), h.host_key, h.revision, h.created_at, h.updated_at
	FROM hosts h LEFT JOIN ssh_keys k ON k.id = h.key_id`

func scanHost(r scanner, extra ...any) (Host, error) {
	var h Host
	var created, updated int64
	dest := append([]any{&h.ID, &h.Alias, &h.Name, &h.Address, &h.Port, &h.Username, &h.AuthKind, &h.CredentialID,
		&h.KeyID, &h.KeyLabel, &h.KeyFingerprint, &h.HostKey, &h.Revision, &created, &updated}, extra...)
	err := r.Scan(dest...)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	h.CreatedAt, h.UpdatedAt = fromUnix(created), fromUnix(updated)
	return h, err
}

var (
	ErrAliasTaken = errors.New("alias already in use")
	ErrNoSuchKey  = errors.New("selected key does not exist")
)

func isUnique(err error) bool { return err != nil && strings.Contains(err.Error(), "UNIQUE") }

func isForeignKey(err error) bool { return err != nil && strings.Contains(err.Error(), "FOREIGN KEY") }

// CreateHost stores a host with its pinned host key and authentication.
func (s *Store) CreateHost(ctx context.Context, spec HostSpec, hostKey []byte, auth HostAuth) (Host, error) {
	now := s.now().UTC().Truncate(time.Second)
	id := NewID()
	keyID, credID, blob := s.authColumns(id, auth)
	_, err := s.db.ExecContext(ctx, `INSERT INTO hosts (id, alias, name, address, port, username, auth_kind, credential_id, key_id, credential, host_key, revision, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,?)`,
		id, spec.Alias, spec.Name, spec.Address, spec.Port, spec.Username, auth.Kind, credID, keyID, blob, hostKey, unix(now), unix(now))
	switch {
	case isUnique(err):
		return Host{}, ErrAliasTaken
	case isForeignKey(err):
		return Host{}, ErrNoSuchKey
	case err != nil:
		return Host{}, err
	}
	return s.GetHost(ctx, id)
}

// HostUpdate replaces metadata. A nil HostKey keeps the pin and is only
// allowed when the endpoint is unchanged. A nil Auth keeps the saved one.
type HostUpdate struct {
	Spec    HostSpec
	HostKey []byte
	Auth    *HostAuth
}

var ErrTrustRequired = errors.New("address or port changed: verify the new host key before saving")

func (s *Store) UpdateHost(ctx context.Context, id string, expectedRevision int64, u HostUpdate) (Host, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Host{}, err
	}
	defer tx.Rollback()
	h, err := scanHost(tx.QueryRowContext(ctx, hostSelect+` WHERE h.id=?`, id))
	if err != nil {
		return Host{}, err
	}
	if h.Revision != expectedRevision {
		return Host{}, ErrConflict
	}
	if u.HostKey == nil && (h.Address != u.Spec.Address || h.Port != u.Spec.Port) {
		return Host{}, ErrTrustRequired
	}
	hostKey := h.HostKey
	if u.HostKey != nil {
		hostKey = u.HostKey
	}
	if u.Auth != nil {
		keyID, credID, blob := s.authColumns(id, *u.Auth)
		_, err = tx.ExecContext(ctx, `UPDATE hosts SET auth_kind=?, key_id=?, credential_id=?, credential=? WHERE id=?`, u.Auth.Kind, keyID, credID, blob, id)
		if isForeignKey(err) {
			return Host{}, ErrNoSuchKey
		}
		if err != nil {
			return Host{}, err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE hosts SET alias=?, name=?, address=?, port=?, username=?, host_key=?, revision=?, updated_at=? WHERE id=?`,
		u.Spec.Alias, u.Spec.Name, u.Spec.Address, u.Spec.Port, u.Spec.Username, hostKey, h.Revision+1, unix(s.now()), id)
	if isUnique(err) {
		return Host{}, ErrAliasTaken
	}
	if err != nil {
		return Host{}, err
	}
	if err := tx.Commit(); err != nil {
		return Host{}, err
	}
	return s.GetHost(ctx, id)
}

func (s *Store) DeleteHost(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM hosts WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListHosts(ctx context.Context) ([]Host, error) {
	rows, err := s.db.QueryContext(ctx, hostSelect+` ORDER BY h.alias`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) GetHost(ctx context.Context, id string) (Host, error) {
	return scanHost(s.db.QueryRowContext(ctx, hostSelect+` WHERE h.id=?`, id))
}

// HostSnapshot loads an immutable copy of the host and its decrypted
// credential for one connection.
func (s *Store) HostSnapshot(ctx context.Context, id string) (Host, Credential, error) {
	var blob []byte
	h, err := scanHost(s.db.QueryRowContext(ctx, hostSelectWithCredential+` WHERE h.id=?`, id), &blob)
	if err != nil {
		return Host{}, Credential{}, err
	}
	if h.AuthKind == AuthKey {
		c, err := s.KeyCredential(ctx, h.KeyID)
		return h, c, err
	}
	pt, err := s.Key.Open(secrets.PurposeTargetCred, passwordAAD(h.ID, h.CredentialID), blob)
	if err != nil {
		return Host{}, Credential{}, err
	}
	return h, Credential{Kind: AuthPassword, Password: string(pt)}, nil
}

const hostSelectWithCredential = `SELECT h.id, h.alias, h.name, h.address, h.port, h.username, h.auth_kind, h.credential_id,
	coalesce(h.key_id, ''), coalesce(k.label, ''), coalesce(k.fingerprint, ''), h.host_key, h.revision, h.created_at, h.updated_at, h.credential
	FROM hosts h LEFT JOIN ssh_keys k ON k.id = h.key_id`

// Upload ledger: records temp files created on targets so interrupted
// uploads can be cleaned up after a restart.

type PendingUpload struct{ ID, HostID, TempPath string }

func (s *Store) RecordUpload(ctx context.Context, u PendingUpload) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO uploads (id, host_id, temp_path, created_at) VALUES (?, ?, ?, ?)`, u.ID, u.HostID, u.TempPath, unix(s.now()))
	return err
}

func (s *Store) ForgetUpload(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM uploads WHERE id=?`, id)
	return err
}

func (s *Store) PendingUploads(ctx context.Context) ([]PendingUpload, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, host_id, temp_path FROM uploads`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingUpload
	for rows.Next() {
		var u PendingUpload
		if err := rows.Scan(&u.ID, &u.HostID, &u.TempPath); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
