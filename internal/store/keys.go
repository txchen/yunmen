package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/txchen/yunmen/internal/secrets"
	"golang.org/x/crypto/ssh"
)

// KeyMaterial is a parsed, unencrypted private key ready to store.
type KeyMaterial struct {
	PEM         []byte
	Type        string
	Fingerprint string
	PublicKey   string // authorized_keys format without a comment
}

// KeyMaterialFromPEM describes an unencrypted private key in any format
// x/crypto/ssh parses. Callers normalize and validate key policy first.
func KeyMaterialFromPEM(pemBytes []byte) (KeyMaterial, error) {
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return KeyMaterial{}, err
	}
	pub := signer.PublicKey()
	return KeyMaterial{
		PEM:         pemBytes,
		Type:        pub.Type(),
		Fingerprint: ssh.FingerprintSHA256(pub),
		PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
	}, nil
}

// Key is a library key as shown to the owner. It has no private material.
type Key struct {
	ID          string    `json:"id"`
	Label       string    `json:"label"`
	Type        string    `json:"keyType"`
	Fingerprint string    `json:"fingerprint"`
	PublicKey   string    `json:"publicKey"`
	CreatedAt   time.Time `json:"createdAt"`
	UsedBy      []string  `json:"usedBy"`
}

var (
	ErrKeyExists = errors.New("this key is already in the key library")
	ErrKeyInUse  = errors.New("key is used by hosts; switch them to another key first")
)

func keyAAD(id string) string { return "key/" + id }

// ParseKeyLabel trims and bounds a key label.
func ParseKeyLabel(label string) (string, error) {
	label = strings.TrimSpace(label)
	if label == "" || utf8.RuneCountInString(label) > 64 || strings.ContainsAny(label, "\r\n\x00") {
		return "", errors.New("key label must be 1-64 characters on one line")
	}
	return label, nil
}

type execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func (s *Store) insertKey(ctx context.Context, db execer, label string, m KeyMaterial) (string, error) {
	id := NewID()
	_, err := db.ExecContext(ctx, `INSERT INTO ssh_keys (id, label, key_type, fingerprint, public_key, secret, created_at) VALUES (?,?,?,?,?,?,?)`,
		id, label, m.Type, m.Fingerprint, m.PublicKey, s.Key.Seal(secrets.PurposeTargetCred, keyAAD(id), m.PEM), unix(s.now()))
	if isUnique(err) {
		return "", ErrKeyExists
	}
	return id, err
}

func (s *Store) CreateKey(ctx context.Context, label string, m KeyMaterial) (Key, error) {
	id, err := s.insertKey(ctx, s.db, label, m)
	if err != nil {
		return Key{}, err
	}
	return s.GetKey(ctx, id)
}

// KeyByFingerprint finds a library key, so importing the same key twice reuses it.
func (s *Store) KeyByFingerprint(ctx context.Context, fp string) (Key, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM ssh_keys WHERE fingerprint=?`, fp).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return Key{}, ErrNotFound
	}
	if err != nil {
		return Key{}, err
	}
	return s.GetKey(ctx, id)
}

func (s *Store) GetKey(ctx context.Context, id string) (Key, error) {
	keys, err := s.listKeys(ctx, `WHERE id=?`, id)
	if err != nil {
		return Key{}, err
	}
	if len(keys) == 0 {
		return Key{}, ErrNotFound
	}
	return keys[0], nil
}

func (s *Store) ListKeys(ctx context.Context) ([]Key, error) {
	return s.listKeys(ctx, `ORDER BY label`)
}

func (s *Store) listKeys(ctx context.Context, where string, args ...any) ([]Key, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, label, key_type, fingerprint, public_key, created_at FROM ssh_keys `+where, args...)
	if err != nil {
		return nil, err
	}
	out := []Key{}
	for rows.Next() {
		var k Key
		var created int64
		if err := rows.Scan(&k.ID, &k.Label, &k.Type, &k.Fingerprint, &k.PublicKey, &created); err != nil {
			rows.Close()
			return nil, err
		}
		k.CreatedAt = fromUnix(created)
		out = append(out, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].UsedBy, err = s.keyUsers(ctx, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) keyUsers(ctx context.Context, id string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT alias FROM hosts WHERE key_id=? ORDER BY alias`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []string{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		users = append(users, a)
	}
	return users, rows.Err()
}

func (s *Store) RenameKey(ctx context.Context, id, label string) (Key, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE ssh_keys SET label=? WHERE id=?`, label, id)
	if err != nil {
		return Key{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Key{}, ErrNotFound
	}
	return s.GetKey(ctx, id)
}

// DeleteKey removes an unused key. It returns ErrKeyInUse with the users.
func (s *Store) DeleteKey(ctx context.Context, id string) ([]string, error) {
	users, err := s.keyUsers(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(users) > 0 {
		return users, ErrKeyInUse
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM ssh_keys WHERE id=?`, id)
	if isForeignKey(err) {
		return nil, ErrKeyInUse
	}
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	return nil, nil
}

// KeyCredential decrypts a library key for one connection.
func (s *Store) KeyCredential(ctx context.Context, id string) (Credential, error) {
	var blob []byte
	err := s.db.QueryRowContext(ctx, `SELECT secret FROM ssh_keys WHERE id=?`, id).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, ErrNotFound
	}
	if err != nil {
		return Credential{}, err
	}
	pt, err := s.Key.Open(secrets.PurposeTargetCred, keyAAD(id), blob)
	if err != nil {
		return Credential{}, err
	}
	return Credential{Kind: AuthKey, KeyID: id, PrivateKey: pt}, nil
}
