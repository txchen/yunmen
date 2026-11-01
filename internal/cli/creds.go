package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

// Config is non-secret client state, stored in ordinary configuration.
type Config struct {
	Gateway   string `json:"gateway"`
	DeviceID  string `json:"deviceId"`
	Label     string `json:"label"`
	ExpiresAt string `json:"expiresAt"`
	// SecretStore records where Secrets live: "keyring" or "file".
	SecretStore string `json:"secretStore"`
}

// Secrets never include the owner password, TOTP data or target credentials.
type Secrets struct {
	AccessClientID     string `json:"accessClientId,omitempty"`
	AccessClientSecret string `json:"accessClientSecret,omitempty"`
	DeviceToken        string `json:"deviceToken"`
}

const keyringService = "yunmen"

func configDir() (string, error) {
	if d := os.Getenv("YUNMEN_CONFIG_DIR"); d != "" {
		return d, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "yunmen"), nil
}

func readJSONFile(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// writePrivate writes atomically with mode 0600 in a 0700 directory.
func writePrivate(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func LoadConfig() (Config, error) {
	dir, err := configDir()
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := readJSONFile(filepath.Join(dir, "config.json"), &c); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, errors.New("not logged in; run `yunmen login <gateway-url>`")
		}
		return Config{}, err
	}
	return c, nil
}

func SaveConfig(c Config) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	return writePrivate(filepath.Join(dir, "config.json"), c)
}

func keyringDisabled() bool { return os.Getenv("YUNMEN_NO_KEYRING") == "1" }

// SaveSecrets prefers the OS credential store and falls back to an owner-only
// file. It returns where the secrets went.
func SaveSecrets(gateway string, s Secrets) (string, error) {
	b, _ := json.Marshal(s)
	if !keyringDisabled() {
		if err := keyring.Set(keyringService, gateway, string(b)); err == nil {
			removeSecretsFile()
			return "keyring", nil
		}
	}
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return "file", writePrivate(filepath.Join(dir, "secrets.json"), s)
}

func LoadSecrets(c Config) (Secrets, error) {
	var s Secrets
	switch c.SecretStore {
	case "keyring":
		v, err := keyring.Get(keyringService, c.Gateway)
		if err != nil {
			return s, fmt.Errorf("read credentials from the OS keyring: %w", err)
		}
		return s, json.Unmarshal([]byte(v), &s)
	case "file":
		dir, err := configDir()
		if err != nil {
			return s, err
		}
		return s, readJSONFile(filepath.Join(dir, "secrets.json"), &s)
	}
	return s, errors.New("no stored credentials; run `yunmen login`")
}

func removeSecretsFile() {
	if dir, err := configDir(); err == nil {
		os.Remove(filepath.Join(dir, "secrets.json"))
	}
}

// DeleteLocal removes every local credential and the config.
func DeleteLocal(c Config) error {
	var errs []error
	if c.SecretStore == "keyring" {
		if err := keyring.Delete(keyringService, c.Gateway); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			errs = append(errs, err)
		}
	}
	dir, err := configDir()
	if err != nil {
		return err
	}
	for _, f := range []string{"secrets.json", "config.json"} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func SecretsLocation(c Config) string {
	if c.SecretStore == "keyring" {
		return "the OS credential store (service \"yunmen\")"
	}
	dir, _ := configDir()
	return filepath.Join(dir, "secrets.json") + " (readable only by you)"
}
