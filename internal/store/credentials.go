package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/txchen/yunmen/internal/secrets"
)

// NewID returns a random opaque identifier.
func NewID() string {
	b := make([]byte, 12)
	mustRand(b)
	return hex.EncodeToString(b)
}

// NewToken returns a high-entropy bearer token and the hash stored for it.
func NewToken(prefix string) (raw string, hash []byte) {
	b := make([]byte, 32)
	mustRand(b)
	raw = prefix + base64.RawURLEncoding.EncodeToString(b)
	return raw, HashToken(raw)
}

func HashToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

func mustRand(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
}

// Owner is the single account. TOTPSecret is decrypted.
type Owner struct {
	PasswordHash string
	TOTPSecret   []byte
	LastStep     int64
}

var ErrNoOwner = errors.New("owner not initialized; run `yunmen-server init` locally")

func (s *Store) HasOwner(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM owner`).Scan(&n)
	return n > 0, err
}

func (s *Store) CreateOwner(ctx context.Context, passwordHash string, totpSecret []byte) error {
	enc := s.Key.Seal(secrets.PurposeTOTP, "owner", totpSecret)
	_, err := s.db.ExecContext(ctx, `INSERT INTO owner (id, password_hash, totp_secret, created_at) VALUES (1, ?, ?, ?)`,
		passwordHash, enc, unix(s.now()))
	if err != nil {
		return errors.New("owner already exists; use the reset commands for recovery")
	}
	return nil
}

func (s *Store) Owner(ctx context.Context) (Owner, error) {
	var o Owner
	var enc []byte
	err := s.db.QueryRowContext(ctx, `SELECT password_hash, totp_secret, totp_last_step FROM owner WHERE id=1`).Scan(&o.PasswordHash, &enc, &o.LastStep)
	if errors.Is(err, sql.ErrNoRows) {
		return Owner{}, ErrNoOwner
	}
	if err != nil {
		return Owner{}, err
	}
	o.TOTPSecret, err = s.Key.Open(secrets.PurposeTOTP, "owner", enc)
	return o, err
}

// AcceptTOTPStep records step as used. It returns false when the step (or a
// later one) was already accepted, which defeats concurrent replay.
func (s *Store) AcceptTOTPStep(ctx context.Context, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE owner SET totp_last_step=? WHERE id=1 AND totp_last_step < ?`, step, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ResetOwnerSecrets replaces the password hash and/or TOTP secret (local
// recovery) and revokes every browser session and device.
func (s *Store) ResetOwnerSecrets(ctx context.Context, passwordHash string, totpSecret []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if passwordHash != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE owner SET password_hash=? WHERE id=1`, passwordHash); err != nil {
			return err
		}
	}
	if totpSecret != nil {
		enc := s.Key.Seal(secrets.PurposeTOTP, "owner", totpSecret)
		if _, err := tx.ExecContext(ctx, `UPDATE owner SET totp_secret=?, totp_last_step=0 WHERE id=1`, enc); err != nil {
			return err
		}
	}
	now := unix(s.now())
	if _, err := tx.ExecContext(ctx, `UPDATE web_sessions SET revoked_at=? WHERE revoked_at IS NULL`, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET revoked_at=? WHERE revoked_at IS NULL`, now); err != nil {
		return err
	}
	return tx.Commit()
}

const (
	WebSessionTTL = 12 * time.Hour
	DeviceTTL     = 30 * 24 * time.Hour
	SessionPrefix = "yms_"
	DevicePrefix  = "ymd_"
)

type WebSession struct {
	ID        string
	ExpiresAt time.Time
}

func (s *Store) CreateWebSession(ctx context.Context) (string, WebSession, error) {
	raw, hash := NewToken(SessionPrefix)
	now := s.now()
	ws := WebSession{ID: NewID(), ExpiresAt: now.Add(WebSessionTTL).UTC().Truncate(time.Second)}
	_, err := s.db.ExecContext(ctx, `INSERT INTO web_sessions (id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		ws.ID, hash, unix(now), unix(ws.ExpiresAt))
	return raw, ws, err
}

// LookupWebSession returns ErrNotFound for unknown, expired or revoked tokens.
func (s *Store) LookupWebSession(ctx context.Context, raw string) (WebSession, error) {
	var ws WebSession
	var exp int64
	err := s.db.QueryRowContext(ctx, `SELECT id, expires_at FROM web_sessions WHERE token_hash=? AND revoked_at IS NULL AND expires_at > ?`,
		HashToken(raw), unix(s.now())).Scan(&ws.ID, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return WebSession{}, ErrNotFound
	}
	ws.ExpiresAt = fromUnix(exp)
	return ws, err
}

func (s *Store) RevokeWebSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE web_sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, unix(s.now()), id)
	return err
}

type Device struct {
	ID               string     `json:"id"`
	Label            string     `json:"label"`
	ServicePrincipal string     `json:"servicePrincipal"`
	CreatedAt        time.Time  `json:"authorizedAt"`
	ExpiresAt        time.Time  `json:"expiresAt"`
	LastUsedAt       *time.Time `json:"lastUsedAt"`
	RevokedAt        *time.Time `json:"revokedAt"`
}

func (s *Store) CreateDevice(ctx context.Context, label, principal string) (string, Device, error) {
	raw, hash := NewToken(DevicePrefix)
	now := s.now().UTC().Truncate(time.Second)
	d := Device{ID: NewID(), Label: label, ServicePrincipal: principal, CreatedAt: now, ExpiresAt: now.Add(DeviceTTL)}
	_, err := s.db.ExecContext(ctx, `INSERT INTO devices (id, label, token_hash, service_principal, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		d.ID, d.Label, hash, d.ServicePrincipal, unix(d.CreatedAt), unix(d.ExpiresAt))
	return raw, d, err
}

// LookupDevice returns ErrNotFound for unknown, expired or revoked tokens and
// records last use (at most once a minute).
func (s *Store) LookupDevice(ctx context.Context, raw string) (Device, error) {
	now := unix(s.now())
	row := s.db.QueryRowContext(ctx, `SELECT id, label, service_principal, created_at, expires_at, last_used_at, revoked_at FROM devices
		WHERE token_hash=? AND revoked_at IS NULL AND expires_at > ?`, HashToken(raw), now)
	d, err := scanDevice(row)
	if err != nil {
		return Device{}, err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE devices SET last_used_at=? WHERE id=? AND (last_used_at IS NULL OR last_used_at < ?)`, now, d.ID, now-60)
	return d, err
}

func (s *Store) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, label, service_principal, created_at, expires_at, last_used_at, revoked_at FROM devices ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RevokeDevice marks the device revoked. It is idempotent.
func (s *Store) RevokeDevice(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET revoked_at=coalesce(revoked_at, ?) WHERE id=?`, unix(s.now()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

type scanner interface{ Scan(...any) error }

func scanDevice(r scanner) (Device, error) {
	var d Device
	var created, expires int64
	var last, revoked sql.NullInt64
	err := r.Scan(&d.ID, &d.Label, &d.ServicePrincipal, &created, &expires, &last, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, err
	}
	d.CreatedAt, d.ExpiresAt = fromUnix(created), fromUnix(expires)
	d.LastUsedAt, d.RevokedAt = nullTime(last), nullTime(revoked)
	return d, nil
}

// CredentialActive reports whether a device or web session is still
// unrevoked and unexpired. Used to catch revocations made by another
// process, such as the local recovery commands.
func (s *Store) CredentialActive(ctx context.Context, kind, id string) (bool, error) {
	table := map[string]string{"device": "devices", "web": "web_sessions"}[kind]
	if table == "" {
		return false, nil
	}
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` WHERE id=? AND revoked_at IS NULL AND expires_at > ?`, id, unix(s.now())).Scan(&n)
	return n == 1, err
}
