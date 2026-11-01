// Package secrets loads the master key and provides authenticated encryption
// for recoverable secrets (target credentials, TOTP seeds).
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	EnvKey     = "YUNMEN_MASTER_KEY"
	EnvKeyFile = "YUNMEN_MASTER_KEY_FILE"
	keyLen     = 32
	version1   = 1
)

// Purpose binds a ciphertext to the kind of record that holds it.
type Purpose string

const (
	PurposeKeyCheck   Purpose = "keycheck"
	PurposeTOTP       Purpose = "totp"
	PurposeTargetCred Purpose = "target-credential"
)

type MasterKey struct{ aead cipher.AEAD }

var ErrDecrypt = errors.New("secret could not be decrypted with the configured master key")

// Load reads the key from exactly one of YUNMEN_MASTER_KEY or
// YUNMEN_MASTER_KEY_FILE. It never generates a key.
func Load(getenv func(string) string) (*MasterKey, error) {
	inline, path := getenv(EnvKey), getenv(EnvKeyFile)
	var encoded string
	switch {
	case inline != "" && path != "":
		return nil, fmt.Errorf("set exactly one of %s or %s, not both", EnvKey, EnvKeyFile)
	case inline != "":
		encoded = inline
	case path != "":
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", EnvKeyFile, err)
		}
		encoded = string(b)
	default:
		return nil, fmt.Errorf("master key missing: set %s or %s (generate one with `yunmen-server genkey`)", EnvKey, EnvKeyFile)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != keyLen {
		return nil, fmt.Errorf("master key malformed: expected base64 encoding of %d bytes", keyLen)
	}
	return FromBytes(raw)
}

func FromBytes(raw []byte) (*MasterKey, error) {
	if len(raw) != keyLen {
		return nil, fmt.Errorf("master key must be %d bytes", keyLen)
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &MasterKey{aead: aead}, nil
}

// Generate returns a fresh base64-encoded key for the operator to store.
func Generate() string {
	b := make([]byte, keyLen)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func aad(p Purpose, recordID string) []byte {
	return []byte(fmt.Sprintf("yunmen:v%d:%s:%s", version1, p, recordID))
}

// Seal encrypts plaintext bound to (purpose, recordID). Layout: version || nonce || ciphertext.
func (k *MasterKey) Seal(p Purpose, recordID string, plaintext []byte) []byte {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	out := append([]byte{version1}, nonce...)
	return k.aead.Seal(out, nonce, plaintext, aad(p, recordID))
}

func (k *MasterKey) Open(p Purpose, recordID string, blob []byte) ([]byte, error) {
	ns := k.aead.NonceSize()
	if len(blob) < 1+ns+k.aead.Overhead() || blob[0] != version1 {
		return nil, ErrDecrypt
	}
	pt, err := k.aead.Open(nil, blob[1:1+ns], blob[1+ns:], aad(p, recordID))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

var keyCheckPlaintext = []byte("yunmen master key check")

// NewKeyCheck produces the record stored on first initialization.
func (k *MasterKey) NewKeyCheck() []byte {
	return k.Seal(PurposeKeyCheck, "v1", keyCheckPlaintext)
}

// VerifyKeyCheck fails when the configured key is not the one the database was initialized with.
func (k *MasterKey) VerifyKeyCheck(blob []byte) error {
	pt, err := k.Open(PurposeKeyCheck, "v1", blob)
	if err != nil || subtle.ConstantTimeCompare(pt, keyCheckPlaintext) != 1 {
		return errors.New("master key does not match this database (key check failed); refusing to start")
	}
	return nil
}
