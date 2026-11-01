package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/txchen/yunmen/internal/secrets"
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
	if _, err := s.CreateHost(ctx, spec, []byte("hostkey"), Credential{Kind: AuthPassword, Password: "hunter2-target"}, ""); err != nil {
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
	h, _ := s.CreateHost(ctx, spec, []byte("k"), Credential{Kind: AuthPassword, Password: "p"}, "")
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
