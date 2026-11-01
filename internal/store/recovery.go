package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"strings"
)

// Recovery codes: 10 one-time codes of 10 characters from a 32-symbol
// alphabet (50 bits each), stored as SHA-256 hashes. High entropy plus the
// login rate limit makes a slow hash unnecessary.
const (
	RecoveryCodeCount = 10
	recoveryAlphabet  = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

// NormalizeRecoveryCode uppercases and drops dashes and spaces.
func NormalizeRecoveryCode(c string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		if r >= 'a' && r <= 'z' {
			return r - 'a' + 'A'
		}
		return r
	}, c)
}

func newRecoveryCode() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = recoveryAlphabet[int(b[i])%len(recoveryAlphabet)]
	}
	return string(b[:5]) + "-" + string(b[5:])
}

func recoveryHash(code string) []byte { return HashToken("recovery:" + NormalizeRecoveryCode(code)) }

// ReplaceRecoveryCodes discards every existing code and returns new ones.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	codes, err := s.replaceRecoveryCodesTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	return codes, tx.Commit()
}

func (s *Store) replaceRecoveryCodesTx(ctx context.Context, tx *sql.Tx) ([]string, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes`); err != nil {
		return nil, err
	}
	codes := make([]string, RecoveryCodeCount)
	for i := range codes {
		codes[i] = newRecoveryCode()
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes (hash, created_at) VALUES (?, ?)`, recoveryHash(codes[i]), unix(s.now())); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

// RecoveryCodeUnused reports whether code is a valid, unused recovery code.
func (s *Store) RecoveryCodeUnused(ctx context.Context, code string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM recovery_codes WHERE hash=? AND used_at IS NULL`, recoveryHash(code)).Scan(&n)
	return n == 1, err
}

// RecoverWithCode atomically uses up code and replaces the TOTP secret,
// revoking every session and device. It returns false if code was already
// used (for example by a concurrent request) and changes nothing then.
func (s *Store) RecoverWithCode(ctx context.Context, code string, totpSecret []byte, acceptedStep int64) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE recovery_codes SET used_at=? WHERE hash=? AND used_at IS NULL`, unix(s.now()), recoveryHash(code))
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return false, nil
	}
	if err := s.resetOwnerTx(ctx, tx, "", totpSecret); err != nil {
		return false, err
	}
	// The confirmation code must not also work as a login code.
	if _, err := tx.ExecContext(ctx, `UPDATE owner SET totp_last_step=? WHERE id=1`, acceptedStep); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (s *Store) RecoveryCodesRemaining(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM recovery_codes WHERE used_at IS NULL`).Scan(&n)
	return n, err
}
