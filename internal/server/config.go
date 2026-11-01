package server

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/txchen/yunmen/internal/auth"
)

type Mode string

const (
	ModeAccess     Mode = "access"
	ModeStandalone Mode = "standalone"
)

// StandalonePrincipal is the service principal recorded for devices paired in
// standalone mode, where no Access service token exists.
const StandalonePrincipal = "standalone"

type Config struct {
	Mode    Mode
	Listen  string
	DataDir string
	Origin  *url.URL // exact browser origin, e.g. https://yunmen.example.com
	Access  auth.AccessConfig
}

func (c Config) DBPath() string { return filepath.Join(c.DataDir, "yunmen.db") }

func (c Config) OriginString() string { return c.Origin.Scheme + "://" + c.Origin.Host }

// SecureCookies is false only for an explicit loopback http development origin.
func (c Config) SecureCookies() bool { return c.Origin.Scheme == "https" }

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// LoadConfig parses environment configuration. The mode must be explicit:
// a missing Access setting is an error, never a fallback to standalone.
func LoadConfig(getenv func(string) string) (Config, error) {
	c := Config{
		Mode:    Mode(getenv("YUNMEN_MODE")),
		Listen:  getenv("YUNMEN_LISTEN"),
		DataDir: getenv("YUNMEN_DATA_DIR"),
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	var errs []error
	origin := getenv("YUNMEN_PUBLIC_ORIGIN")
	u, err := url.Parse(origin)
	switch {
	case origin == "":
		errs = append(errs, errors.New("YUNMEN_PUBLIC_ORIGIN is required (e.g. https://yunmen.example.com)"))
	case err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil:
		errs = append(errs, errors.New("YUNMEN_PUBLIC_ORIGIN must be a bare origin like https://yunmen.example.com"))
	case u.Scheme == "http" && !isLoopback(u.Hostname()):
		errs = append(errs, errors.New("YUNMEN_PUBLIC_ORIGIN must use https (http is accepted only for localhost development)"))
	case u.Scheme != "https" && u.Scheme != "http":
		errs = append(errs, errors.New("YUNMEN_PUBLIC_ORIGIN must use https"))
	default:
		u.Path = ""
		c.Origin = u
	}
	switch c.Mode {
	case ModeAccess:
		c.Access = auth.AccessConfig{
			TeamDomain:       strings.TrimRight(getenv("YUNMEN_ACCESS_TEAM_DOMAIN"), "/"),
			Audience:         getenv("YUNMEN_ACCESS_AUD"),
			OwnerEmails:      splitList(getenv("YUNMEN_ACCESS_OWNER_EMAILS")),
			ServiceClientIDs: splitList(getenv("YUNMEN_ACCESS_SERVICE_CLIENT_IDS")),
		}
		if td, err := url.Parse(c.Access.TeamDomain); err != nil || td.Scheme != "https" || td.Host == "" {
			errs = append(errs, errors.New("YUNMEN_ACCESS_TEAM_DOMAIN must be https://<team>.cloudflareaccess.com"))
		}
		if c.Access.Audience == "" {
			errs = append(errs, errors.New("YUNMEN_ACCESS_AUD (application audience tag) is required"))
		}
		if len(c.Access.OwnerEmails) == 0 {
			errs = append(errs, errors.New("YUNMEN_ACCESS_OWNER_EMAILS is required"))
		}
		if len(c.Access.ServiceClientIDs) == 0 {
			errs = append(errs, errors.New("YUNMEN_ACCESS_SERVICE_CLIENT_IDS is required (Client IDs of service tokens allowed to use the CLI)"))
		}
	case ModeStandalone:
	case "":
		errs = append(errs, errors.New("YUNMEN_MODE is required: `access` (behind Cloudflare Access) or `standalone`"))
	default:
		errs = append(errs, fmt.Errorf("YUNMEN_MODE %q is invalid: use `access` or `standalone`", c.Mode))
	}
	return c, errors.Join(errs...)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
