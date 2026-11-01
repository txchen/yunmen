package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessHeader is the header Cloudflare Access adds to every proxied request.
const AccessHeader = "Cf-Access-Jwt-Assertion"

// AccessConfig describes the Cloudflare Access application protecting Yunmen.
type AccessConfig struct {
	TeamDomain       string   // https://<team>.cloudflareaccess.com
	Audience         string   // application AUD tag
	OwnerEmails      []string // browser identities treated as the owner
	ServiceClientIDs []string // service token Client IDs allowed to use the CLI
}

type PrincipalKind int

const (
	PrincipalOwner PrincipalKind = iota + 1
	PrincipalService
)

// AccessIdentity is a verified Access assertion mapped to a Yunmen principal.
type AccessIdentity struct {
	Kind      PrincipalKind
	Subject   string // owner email, or service token Client ID
	ExpiresAt time.Time
}

type accessClaims struct {
	jwt.RegisteredClaims
	Email      string `json:"email"`
	CommonName string `json:"common_name"`
	Type       string `json:"type"`
}

type AccessVerifier struct {
	cfg    AccessConfig
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	attemptAt time.Time
}

func NewAccessVerifier(cfg AccessConfig, client *http.Client) *AccessVerifier {
	cfg.TeamDomain = strings.TrimRight(cfg.TeamDomain, "/")
	return &AccessVerifier{cfg: cfg, client: client, now: time.Now}
}

var ErrAccessDenied = errors.New("cloudflare access assertion rejected")

// Verify checks signature (RS256 only), issuer, audience and expiry, then maps
// the claims to an explicitly allowed principal.
func (v *AccessVerifier) Verify(ctx context.Context, token string) (AccessIdentity, error) {
	if token == "" {
		return AccessIdentity{}, ErrAccessDenied
	}
	var claims accessClaims
	_, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return v.key(ctx, kid)
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.cfg.TeamDomain),
		jwt.WithAudience(v.cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(10*time.Second),
		jwt.WithTimeFunc(v.now),
	)
	if err != nil {
		return AccessIdentity{}, fmt.Errorf("%w: %v", ErrAccessDenied, err)
	}
	id := AccessIdentity{ExpiresAt: claims.ExpiresAt.Time}
	switch {
	case claims.CommonName != "" && claims.Subject == "":
		if !contains(v.cfg.ServiceClientIDs, claims.CommonName, false) {
			return AccessIdentity{}, fmt.Errorf("%w: service token not allowed", ErrAccessDenied)
		}
		id.Kind, id.Subject = PrincipalService, claims.CommonName
	case claims.Email != "" && claims.Subject != "":
		if !contains(v.cfg.OwnerEmails, claims.Email, true) {
			return AccessIdentity{}, fmt.Errorf("%w: identity is not the owner", ErrAccessDenied)
		}
		id.Kind, id.Subject = PrincipalOwner, strings.ToLower(claims.Email)
	default:
		return AccessIdentity{}, fmt.Errorf("%w: unrecognized principal", ErrAccessDenied)
	}
	return id, nil
}

func contains(list []string, s string, fold bool) bool {
	for _, x := range list {
		if x == s || (fold && strings.EqualFold(x, s)) {
			return true
		}
	}
	return false
}

// key returns the signing key for kid. Certs are cached for an hour and
// refetched at most once a minute (for rotation); the fetch runs without
// holding the lock so a slow certs endpoint cannot stall cached lookups.
func (v *AccessVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	now := v.now()
	k, ok := v.keys[kid]
	fresh := ok && now.Sub(v.fetchedAt) < time.Hour
	mayFetch := now.Sub(v.attemptAt) > time.Minute
	if !fresh && mayFetch {
		v.attemptAt = now
	}
	v.mu.Unlock()
	if fresh || !mayFetch {
		if ok {
			return k, nil
		}
		return nil, errors.New("unknown signing key")
	}
	keys, err := v.fetch(ctx)
	v.mu.Lock()
	defer v.mu.Unlock()
	if err == nil {
		v.keys, v.fetchedAt = keys, now
	}
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errors.New("unknown signing key")
}

func (v *AccessVerifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.TeamDomain+"/cdn-cgi/access/certs", nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch access certs: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch access certs: status %d", resp.StatusCode)
	}
	var body struct {
		Keys []struct {
			Kid, Kty, Alg, N, E string
		} `json:"keys"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode access certs: %w", err)
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range body.Keys {
		if k.Kty != "RSA" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) > 4 {
			continue
		}
		out[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if len(out) == 0 {
		return nil, errors.New("access certs contained no RSA keys")
	}
	return out, nil
}
