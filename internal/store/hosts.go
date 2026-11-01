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

func credAAD(hostID, credID string) string { return hostID + "/" + credID }

func (s *Store) sealCredential(hostID, credID string, c Credential) []byte {
	var pt []byte
	if c.Kind == AuthKey {
		pt = c.PrivateKey
	} else {
		pt = []byte(c.Password)
	}
	return s.Key.Seal(secrets.PurposeTargetCred, credAAD(hostID, credID), pt)
}

const hostCols = `id, alias, name, address, port, username, auth_kind, credential_id, key_fingerprint, host_key, revision, created_at, updated_at`

func scanHost(r scanner) (Host, error) {
	var h Host
	var created, updated int64
	err := r.Scan(&h.ID, &h.Alias, &h.Name, &h.Address, &h.Port, &h.Username, &h.AuthKind, &h.CredentialID, &h.KeyFingerprint, &h.HostKey, &h.Revision, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	h.CreatedAt, h.UpdatedAt = fromUnix(created), fromUnix(updated)
	return h, err
}

var ErrAliasTaken = errors.New("alias already in use")

func isUnique(err error) bool { return err != nil && strings.Contains(err.Error(), "UNIQUE") }

// CreateHost stores a host with its pinned host key and encrypted credential.
func (s *Store) CreateHost(ctx context.Context, spec HostSpec, hostKey []byte, cred Credential, keyFingerprint string) (Host, error) {
	now := s.now().UTC().Truncate(time.Second)
	h := Host{ID: NewID(), Alias: spec.Alias, Name: spec.Name, Address: spec.Address, Port: spec.Port, Username: spec.Username,
		AuthKind: cred.Kind, KeyFingerprint: keyFingerprint, HostKey: hostKey, CredentialID: NewID(), Revision: 1, CreatedAt: now, UpdatedAt: now}
	_, err := s.db.ExecContext(ctx, `INSERT INTO hosts (`+hostCols+`, credential) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		h.ID, h.Alias, h.Name, h.Address, h.Port, h.Username, h.AuthKind, h.CredentialID, h.KeyFingerprint, h.HostKey, h.Revision, unix(now), unix(now),
		s.sealCredential(h.ID, h.CredentialID, cred))
	if isUnique(err) {
		return Host{}, ErrAliasTaken
	}
	return h, err
}

// HostUpdate replaces metadata. A nil HostKey keeps the pin and is only
// allowed when the endpoint is unchanged. A nil Credential keeps the saved one.
type HostUpdate struct {
	Spec           HostSpec
	HostKey        []byte
	Credential     *Credential
	KeyFingerprint string
}

var ErrTrustRequired = errors.New("address or port changed: verify the new host key before saving")

func (s *Store) UpdateHost(ctx context.Context, id string, expectedRevision int64, u HostUpdate) (Host, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Host{}, err
	}
	defer tx.Rollback()
	h, err := scanHost(tx.QueryRowContext(ctx, `SELECT `+hostCols+` FROM hosts WHERE id=?`, id))
	if err != nil {
		return Host{}, err
	}
	if h.Revision != expectedRevision {
		return Host{}, ErrConflict
	}
	if u.HostKey == nil && (h.Address != u.Spec.Address || h.Port != u.Spec.Port) {
		return Host{}, ErrTrustRequired
	}
	h.Alias, h.Name, h.Address, h.Port, h.Username = u.Spec.Alias, u.Spec.Name, u.Spec.Address, u.Spec.Port, u.Spec.Username
	if u.HostKey != nil {
		h.HostKey = u.HostKey
	}
	h.Revision++
	h.UpdatedAt = s.now().UTC().Truncate(time.Second)
	if u.Credential != nil {
		h.AuthKind, h.CredentialID, h.KeyFingerprint = u.Credential.Kind, NewID(), u.KeyFingerprint
		_, err = tx.ExecContext(ctx, `UPDATE hosts SET credential=?, credential_id=?, auth_kind=?, key_fingerprint=? WHERE id=?`,
			s.sealCredential(h.ID, h.CredentialID, *u.Credential), h.CredentialID, h.AuthKind, h.KeyFingerprint, id)
		if err != nil {
			return Host{}, err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE hosts SET alias=?, name=?, address=?, port=?, username=?, host_key=?, revision=?, updated_at=? WHERE id=?`,
		h.Alias, h.Name, h.Address, h.Port, h.Username, h.HostKey, h.Revision, unix(h.UpdatedAt), id)
	if isUnique(err) {
		return Host{}, ErrAliasTaken
	}
	if err != nil {
		return Host{}, err
	}
	return h, tx.Commit()
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
	rows, err := s.db.QueryContext(ctx, `SELECT `+hostCols+` FROM hosts ORDER BY alias`)
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
	return scanHost(s.db.QueryRowContext(ctx, `SELECT `+hostCols+` FROM hosts WHERE id=?`, id))
}

// HostSnapshot loads an immutable copy of the host and its decrypted credential
// for one connection.
func (s *Store) HostSnapshot(ctx context.Context, id string) (Host, Credential, error) {
	var blob []byte
	row := s.db.QueryRowContext(ctx, `SELECT `+hostCols+`, credential FROM hosts WHERE id=?`, id)
	var h Host
	var created, updated int64
	err := row.Scan(&h.ID, &h.Alias, &h.Name, &h.Address, &h.Port, &h.Username, &h.AuthKind, &h.CredentialID, &h.KeyFingerprint, &h.HostKey, &h.Revision, &created, &updated, &blob)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, Credential{}, ErrNotFound
	}
	if err != nil {
		return Host{}, Credential{}, err
	}
	h.CreatedAt, h.UpdatedAt = fromUnix(created), fromUnix(updated)
	pt, err := s.Key.Open(secrets.PurposeTargetCred, credAAD(h.ID, h.CredentialID), blob)
	if err != nil {
		return Host{}, Credential{}, err
	}
	c := Credential{Kind: h.AuthKind}
	if c.Kind == AuthKey {
		c.PrivateKey = pt
	} else {
		c.Password = string(pt)
	}
	return h, c, nil
}

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
