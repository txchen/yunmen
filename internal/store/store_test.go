package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/txchen/yunmen/internal/secrets"
	"golang.org/x/crypto/ssh"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestMasterKeyConfiguration(t *testing.T) {
	good := secrets.Generate()
	file := filepath.Join(t.TempDir(), "key")
	os.WriteFile(file, []byte(good+"\n"), 0o600)
	cases := []struct {
		name string
		env  map[string]string
		ok   bool
	}{
		{"env", map[string]string{secrets.EnvKey: good}, true},
		{"file", map[string]string{secrets.EnvKeyFile: file}, true},
		{"missing", map[string]string{}, false},
		{"both", map[string]string{secrets.EnvKey: good, secrets.EnvKeyFile: file}, false},
		{"malformed", map[string]string{secrets.EnvKey: "not base64!"}, false},
		{"short", map[string]string{secrets.EnvKey: base64.StdEncoding.EncodeToString([]byte("short"))}, false},
		{"unreadable file", map[string]string{secrets.EnvKeyFile: file + ".missing"}, false},
	}
	for _, c := range cases {
		_, err := secrets.Load(env(c.env))
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v", c.name, err)
		}
		if err != nil && strings.Contains(err.Error(), good) {
			t.Errorf("%s: error message leaks the key", c.name)
		}
	}
}

func TestWrongMasterKeyRefusedWithoutMutation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "y.db")
	k1, _ := secrets.FromBytes(bytes.Repeat([]byte{1}, 32))
	s, err := Open(ctx, path, k1)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := ParseHostSpec("box", "", "10.0.0.1", "me", 22)
	if _, err := s.CreateHost(ctx, spec, []byte("hostkey"), HostAuth{Kind: AuthPassword, Password: "hunter2-target"}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("hunter2-target")) {
		t.Fatal("target password stored in plaintext")
	}
	before := snapshot(t, path)

	k2, _ := secrets.FromBytes(bytes.Repeat([]byte{2}, 32))
	if _, err := Open(ctx, path, k2); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong key accepted: %v", err)
	}
	if snapshot(t, path) != before {
		t.Fatal("database changed after a rejected key")
	}

	s, err = Open(ctx, path, k1)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	hosts, _ := s.ListHosts(ctx)
	_, cred, err := s.HostSnapshot(ctx, hosts[0].ID)
	if err != nil || cred.Password != "hunter2-target" {
		t.Fatalf("decrypt after reopen: %v", err)
	}
}

func snapshot(t *testing.T, path string) string {
	var b strings.Builder
	for _, p := range []string{path, path + "-wal"} {
		raw, _ := os.ReadFile(p)
		b.Write(raw)
	}
	return b.String()
}

func TestCiphertextBoundToRecord(t *testing.T) {
	k, _ := secrets.FromBytes(bytes.Repeat([]byte{3}, 32))
	blob := k.Seal(secrets.PurposeTargetCred, "host-a/cred-1", []byte("secret"))
	if _, err := k.Open(secrets.PurposeTargetCred, "host-b/cred-1", blob); err == nil {
		t.Fatal("ciphertext moved to another record decrypted")
	}
	if _, err := k.Open(secrets.PurposeTOTP, "host-a/cred-1", blob); err == nil {
		t.Fatal("ciphertext decrypted under another purpose")
	}
	blob[len(blob)-1] ^= 1
	if _, err := k.Open(secrets.PurposeTargetCred, "host-a/cred-1", blob); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
}

func TestStaleHostRevisionConflicts(t *testing.T) {
	ctx := context.Background()
	k, _ := secrets.FromBytes(bytes.Repeat([]byte{4}, 32))
	s, _ := Open(ctx, filepath.Join(t.TempDir(), "y.db"), k)
	defer s.Close()
	spec, _ := ParseHostSpec("box", "", "10.0.0.1", "me", 22)
	h, _ := s.CreateHost(ctx, spec, []byte("k"), HostAuth{Kind: AuthPassword, Password: "p"})
	renamed := spec
	renamed.Name = "first"
	if _, err := s.UpdateHost(ctx, h.ID, h.Revision, HostUpdate{Spec: renamed}); err != nil {
		t.Fatal(err)
	}
	renamed.Name = "second"
	if _, err := s.UpdateHost(ctx, h.ID, h.Revision, HostUpdate{Spec: renamed}); err != ErrConflict {
		t.Fatalf("stale revision: %v", err)
	}
	moved := spec
	moved.Address = "10.0.0.2"
	if _, err := s.UpdateHost(ctx, h.ID, h.Revision+1, HostUpdate{Spec: moved}); err != ErrTrustRequired {
		t.Fatalf("endpoint change without new host key: %v", err)
	}
}

func testKeyPEM(t *testing.T) []byte {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

// A schema-1 database keeps private keys inside each host row. Upgrading
// moves them into the key library, shared when two hosts use the same key.
func TestMigrationMovesHostKeysIntoLibrary(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "y.db")
	k, _ := secrets.FromBytes(bytes.Repeat([]byte{5}, 32))

	v1, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := v1.BeginTx(ctx, nil)
	for _, step := range migrations[0] {
		if err := step(ctx, tx, nil); err != nil {
			t.Fatal(err)
		}
	}
	tx.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL); INSERT INTO schema_migrations VALUES (1, 0)`)
	tx.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES (?, ?)`, metaKeyCheck, k.NewKeyCheck())
	keyPEM := testKeyPEM(t)
	for i, alias := range []string{"a", "b", "pw"} {
		id, credID := NewID(), NewID()
		kind, secret := "key", keyPEM
		if alias == "pw" {
			kind, secret = "password", []byte("target-pw")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO hosts (id, alias, name, address, port, username, auth_kind, credential_id, credential, key_fingerprint, host_key, revision, created_at, updated_at)
			VALUES (?,?,?,?,22,'me',?,?,?,'', x'00', 1, 0, 0)`, id, alias, alias, "10.0.0."+string(rune('1'+i)), kind, credID,
			k.Seal(secrets.PurposeTargetCred, passwordAAD(id, credID), secret))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	v1.Close()

	var s *Store
	s, err = Open(ctx, path, k)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	keys, _ := s.ListKeys(ctx)
	if len(keys) != 1 || strings.Join(keys[0].UsedBy, ",") != "a,b" {
		t.Fatalf("library after migration: %+v", keys)
	}
	hosts, _ := s.ListHosts(ctx)
	for _, h := range hosts {
		_, cred, err := s.HostSnapshot(ctx, h.ID)
		if err != nil {
			t.Fatalf("%s: %v", h.Alias, err)
		}
		switch h.Alias {
		case "pw":
			if cred.Password != "target-pw" {
				t.Fatalf("password host lost its password")
			}
		default:
			if !bytes.Equal(cred.PrivateKey, keyPEM) || cred.KeyID != keys[0].ID || h.KeyFingerprint != keys[0].Fingerprint {
				t.Fatalf("%s: key not migrated", h.Alias)
			}
		}
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, keyPEM[40:80]) {
		t.Fatal("private key stored in plaintext")
	}
}

func TestKeyLibraryDeleteRefusedWhileUsed(t *testing.T) {
	ctx := context.Background()
	k, _ := secrets.FromBytes(bytes.Repeat([]byte{6}, 32))
	s, _ := Open(ctx, filepath.Join(t.TempDir(), "y.db"), k)
	defer s.Close()
	m, _ := KeyMaterialFromPEM(testKeyPEM(t))
	key, err := s.CreateKey(ctx, "laptop", m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateKey(ctx, "again", m); err != ErrKeyExists {
		t.Fatalf("duplicate key: %v", err)
	}
	spec, _ := ParseHostSpec("box", "", "10.0.0.1", "me", 22)
	h, err := s.CreateHost(ctx, spec, []byte("k"), HostAuth{Kind: AuthKey, KeyID: key.ID})
	if err != nil || h.KeyLabel != "laptop" {
		t.Fatalf("host with library key: %+v %v", h, err)
	}
	if users, err := s.DeleteKey(ctx, key.ID); err != ErrKeyInUse || len(users) != 1 {
		t.Fatalf("delete used key: %v %v", users, err)
	}
	if _, err := s.CreateHost(ctx, spec, []byte("k"), HostAuth{Kind: AuthKey, KeyID: "missing"}); err != ErrNoSuchKey && err != ErrAliasTaken {
		t.Fatalf("unknown key: %v", err)
	}
	s.UpdateHost(ctx, h.ID, h.Revision, HostUpdate{Spec: spec, Auth: &HostAuth{Kind: AuthPassword, Password: "p"}})
	if _, err := s.DeleteKey(ctx, key.ID); err != nil {
		t.Fatalf("delete unused key: %v", err)
	}
}

func TestRecoveryCodeWorksOnce(t *testing.T) {
	ctx := context.Background()
	k, _ := secrets.FromBytes(bytes.Repeat([]byte{8}, 32))
	s, _ := Open(ctx, filepath.Join(t.TempDir(), "y.db"), k)
	defer s.Close()
	codes, err := s.CreateOwner(ctx, "hash", []byte("old-totp"))
	if err != nil || len(codes) != RecoveryCodeCount {
		t.Fatalf("owner creation: %v %d codes", err, len(codes))
	}
	typed := strings.ToLower(strings.ReplaceAll(codes[3], "-", " "))
	if ok, _ := s.RecoveryCodeUnused(ctx, typed); !ok {
		t.Fatal("normalized code not accepted")
	}
	if ok, err := s.RecoverWithCode(ctx, typed, []byte("new-totp"), 99); !ok || err != nil {
		t.Fatalf("recover: %v %v", ok, err)
	}
	if ok, _ := s.RecoverWithCode(ctx, codes[3], []byte("other"), 100); ok {
		t.Fatal("recovery code worked twice")
	}
	if o, _ := s.Owner(ctx); string(o.TOTPSecret) != "new-totp" || o.LastStep != 99 {
		t.Fatalf("owner after recovery: %q step %d", o.TOTPSecret, o.LastStep)
	}
	if n, _ := s.RecoveryCodesRemaining(ctx); n != 9 {
		t.Fatalf("remaining %d", n)
	}
}
