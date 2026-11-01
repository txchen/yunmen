package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/txchen/yunmen/internal/auth"
	"github.com/txchen/yunmen/internal/secrets"
	"github.com/txchen/yunmen/internal/store"
	"github.com/txchen/yunmen/internal/terminal"
	"github.com/txchen/yunmen/internal/testutil"
)

const (
	ownerPassword = "correct horse battery staple"
	ownerEmail    = "owner@example.com"
	serviceID     = "svc-laptop.access"
	audience      = "aud-tag-123"
)

// fakeAccess issues RS256 assertions and serves its JWKS like Cloudflare.
type fakeAccess struct {
	key    *rsa.PrivateKey
	srv    *httptest.Server
	issuer string
}

func newFakeAccess(t *testing.T) *fakeAccess {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fa := &fakeAccess{key: k}
	fa.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": "k1", "kty": "RSA", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		}}})
	}))
	t.Cleanup(fa.srv.Close)
	fa.issuer = fa.srv.URL
	return fa
}

func (fa *fakeAccess) mint(t *testing.T, claims jwt.MapClaims) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(fa.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (fa *fakeAccess) owner(t *testing.T) string {
	return fa.mint(t, jwt.MapClaims{"iss": fa.issuer, "aud": []string{audience}, "sub": "user-1", "email": ownerEmail, "exp": time.Now().Add(time.Hour).Unix()})
}

func (fa *fakeAccess) service(t *testing.T, id string) string {
	return fa.mint(t, jwt.MapClaims{"iss": fa.issuer, "aud": []string{audience}, "sub": "", "common_name": id, "exp": time.Now().Add(time.Hour).Unix()})
}

type harness struct {
	t      *testing.T
	srv    *Server
	http   *httptest.Server
	store  *store.Store
	access *fakeAccess // nil in standalone mode

	mu         sync.Mutex
	totp       []byte
	clockShift time.Duration
}

func newHarness(t *testing.T, mode Mode) *harness {
	t.Helper()
	key, _ := secrets.FromBytes(bytes.Repeat([]byte{7}, 32))
	st, err := store.Open(context.Background(), t.TempDir()+"/y.db", key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h := &harness{t: t, store: st, totp: auth.NewTOTPSecret()}
	hash, _ := auth.HashPassword(ownerPassword)
	if err := st.CreateOwner(context.Background(), hash, h.totp); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Mode: mode}
	var verifier *auth.AccessVerifier
	if mode == ModeAccess {
		h.access = newFakeAccess(t)
		cfg.Access = auth.AccessConfig{TeamDomain: h.access.issuer, Audience: audience, OwnerEmails: []string{ownerEmail}, ServiceClientIDs: []string{serviceID, "svc-other.access"}}
		verifier = auth.NewAccessVerifier(cfg.Access, http.DefaultClient)
	}
	log := slog.New(slog.NewTextHandler(testLogOut(), nil))
	webFS := fstest.MapFS{"index.html": {Data: []byte("<html>yunmen</html>")}}
	// The origin must be known before the listener exists; patch it after start.
	h.srv = New(Options{Config: cfg, Store: st, Access: verifier, Log: log, Web: webFS, Terminal: terminal.Deps{Heartbeat: time.Second}})
	h.srv.now = h.now
	h.http = httptest.NewServer(nil)
	u, _ := url.Parse(h.http.URL)
	h.srv.cfg.Origin = u
	h.http.Config.Handler = h.srv.Handler()
	t.Cleanup(h.http.Close)
	return h
}

func (h *harness) now() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return time.Now().Add(h.clockShift)
}

// code returns a fresh TOTP code by moving the server's TOTP clock one step
// ahead, so repeated logins in one test never collide with replay protection.
func (h *harness) code() string {
	h.mu.Lock()
	h.clockShift += 30 * time.Second
	shift := h.clockShift
	h.mu.Unlock()
	return auth.TOTPCode(h.totp, time.Now().Add(shift))
}

// client is one HTTP actor: a browser (cookies, Origin) or a CLI device.
type client struct {
	h       *harness
	jar     http.CookieJar
	headers http.Header
}

func (h *harness) browser() *client {
	jar, _ := cookiejar.New(nil)
	c := &client{h: h, jar: jar, headers: http.Header{"Origin": {h.http.URL}}}
	if h.access != nil {
		c.headers.Set(auth.AccessHeader, h.access.owner(h.t))
	}
	return c
}

func (h *harness) cli(serviceClientID string) *client {
	c := &client{h: h, headers: http.Header{}}
	if h.access != nil {
		c.headers.Set(auth.AccessHeader, h.access.service(h.t, serviceClientID))
	}
	return c
}

func (c *client) do(method, path string, body any) (int, map[string]any) {
	c.h.t.Helper()
	status, raw := c.raw(method, path, body)
	var m map[string]any
	json.Unmarshal(raw, &m)
	return status, m
}

func (c *client) raw(method, path string, body any) (int, []byte) {
	c.h.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.h.http.URL+path, r)
	for k, v := range c.headers {
		req.Header[k] = v
	}
	hc := &http.Client{Jar: c.jar, Timeout: 60 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (c *client) login() {
	c.h.t.Helper()
	if st, body := c.do("POST", "/api/v1/auth/login", map[string]string{"password": ownerPassword, "code": c.h.code()}); st != 200 {
		c.h.t.Fatalf("login: %d %v", st, body)
	}
}

// pair runs the full CLI approval flow and returns a CLI client holding the token.
func (h *harness) pair(owner *client, serviceClientID, label string) (*client, string) {
	h.t.Helper()
	cli := h.cli(serviceClientID)
	st, start := cli.do("POST", "/api/v1/cli/pair/start", map[string]string{"label": label})
	if st != 200 {
		h.t.Fatalf("pair start: %d %v", st, start)
	}
	code := start["userCode"].(string)
	if st, b := owner.do("POST", "/api/v1/pairings/approve", map[string]string{"userCode": code, "password": ownerPassword, "code": h.code()}); st != 204 {
		h.t.Fatalf("approve: %d %v", st, b)
	}
	h.srv.pairings.mu.Lock()
	for _, p := range h.srv.pairings.byCode {
		p.lastPoll = time.Time{}
	}
	h.srv.pairings.mu.Unlock()
	st, res := cli.do("POST", "/api/v1/cli/pair/poll", map[string]string{"pollToken": start["pollToken"].(string)})
	if st != 200 || res["status"] != "approved" {
		h.t.Fatalf("poll: %d %v", st, res)
	}
	cli.headers.Set("Authorization", "Bearer "+res["deviceToken"].(string))
	return cli, res["deviceId"].(string)
}

// addHost probes and saves target with the given auth; returns the host id.
func (h *harness) addHost(owner *client, alias string, tgt testutil.Target, auth map[string]string) string {
	h.t.Helper()
	st, probe := owner.do("POST", "/api/v1/hosts/probe", map[string]any{"address": tgt.Address, "port": tgt.Port})
	if st != 200 {
		h.t.Fatalf("probe: %d %v", st, probe)
	}
	st, res := owner.do("POST", "/api/v1/hosts", map[string]any{"alias": alias, "name": alias, "address": tgt.Address, "port": tgt.Port,
		"username": tgt.Username, "auth": auth, "observationId": probe["observationId"]})
	if st != 201 {
		h.t.Fatalf("create host: %d %v", st, res)
	}
	return res["host"].(map[string]any)["id"].(string)
}

func keyAuth(tgt testutil.Target) map[string]string {
	return map[string]string{"kind": "key", "privateKey": string(tgt.PrivateKey)}
}

func passwordAuth(tgt testutil.Target) map[string]string {
	return map[string]string{"kind": "password", "password": tgt.Password}
}

func wsURL(h *harness) string {
	return "ws" + strings.TrimPrefix(h.http.URL, "http") + "/api/v1/terminal"
}

func testLogOut() io.Writer {
	if os.Getenv("YUNMEN_TEST_LOG") != "" {
		return os.Stderr
	}
	return io.Discard
}
