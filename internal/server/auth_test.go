package server

import (
	"encoding/base64"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/txchen/yunmen/internal/auth"
	"github.com/txchen/yunmen/internal/testutil"
)

func TestLoginRequiresPasswordAndFreshTOTP(t *testing.T) {
	h := newHarness(t, ModeStandalone)
	b := h.browser()

	if st, _ := b.do("GET", "/api/v1/hosts", nil); st != 401 {
		t.Fatalf("hosts without session: %d", st)
	}
	if st, _ := b.do("POST", "/api/v1/auth/login", map[string]string{"password": ownerPassword, "code": "000000"}); st != 401 {
		t.Fatalf("wrong TOTP accepted: %d", st)
	}
	code := h.code()
	if st, _ := b.do("POST", "/api/v1/auth/login", map[string]string{"password": "wrong password!!", "code": code}); st != 401 {
		t.Fatalf("wrong password accepted: %d", st)
	}
	if st, _ := b.do("POST", "/api/v1/auth/login", map[string]string{"password": ownerPassword, "code": code}); st != 200 {
		t.Fatalf("valid login rejected: %d", st)
	}
	other := h.browser()
	if st, body := other.do("POST", "/api/v1/auth/login", map[string]string{"password": ownerPassword, "code": code}); st != 401 || !strings.Contains(body["error"].(string), "already used") {
		t.Fatalf("replayed TOTP code: %d %v", st, body)
	}
	if st, _ := b.do("GET", "/api/v1/hosts", nil); st != 200 {
		t.Fatalf("hosts with session: %d", st)
	}
	if st, _ := b.do("POST", "/api/v1/auth/logout", map[string]string{}); st != 204 {
		t.Fatalf("logout: %d", st)
	}
	if st, _ := b.do("GET", "/api/v1/hosts", nil); st != 401 {
		t.Fatalf("session survived logout: %d", st)
	}
}

func TestLoginRateLimited(t *testing.T) {
	h := newHarness(t, ModeStandalone)
	b := h.browser()
	for i := 0; i < 5; i++ {
		b.do("POST", "/api/v1/auth/login", map[string]string{"password": "nope nope nope", "code": "123456"})
	}
	if st, _ := b.do("POST", "/api/v1/auth/login", map[string]string{"password": ownerPassword, "code": h.code()}); st != 429 {
		t.Fatalf("expected lockout, got %d", st)
	}
}

func TestWebSessionExpiresAfter12Hours(t *testing.T) {
	h := newHarness(t, ModeStandalone)
	b := h.browser()
	b.login()
	h.store.SetClock(func() time.Time { return time.Now().Add(12*time.Hour + time.Second) })
	if st, _ := b.do("GET", "/api/v1/auth/session", nil); st != 401 {
		t.Fatalf("expired session accepted: %d", st)
	}
}

func TestCrossOriginStateChangeRejected(t *testing.T) {
	h := newHarness(t, ModeStandalone)
	b := h.browser()
	b.login()
	b.headers.Set("Origin", "https://evil.example")
	if st, _ := b.do("POST", "/api/v1/hosts/probe", map[string]any{"address": "127.0.0.1", "port": 22}); st != 403 {
		t.Fatalf("cross-origin POST: %d", st)
	}
	b.headers.Del("Origin")
	if st, _ := b.do("POST", "/api/v1/auth/logout", nil); st != 403 {
		t.Fatalf("POST without Origin: %d", st)
	}
	if _, st := b.dialTerm(); st != 403 {
		t.Fatalf("terminal upgrade without Origin: %d", st)
	}
}

func TestAccessModeRejectsMissingOrInvalidAssertions(t *testing.T) {
	h := newHarness(t, ModeAccess)
	fa := h.access
	exp := time.Now().Add(time.Hour).Unix()
	cases := map[string]string{
		"missing":        "",
		"wrong audience": fa.mint(t, jwt.MapClaims{"iss": fa.issuer, "aud": "other", "sub": "u", "email": ownerEmail, "exp": exp}),
		"wrong issuer":   fa.mint(t, jwt.MapClaims{"iss": "https://evil.cloudflareaccess.com", "aud": audience, "sub": "u", "email": ownerEmail, "exp": exp}),
		"expired":        fa.mint(t, jwt.MapClaims{"iss": fa.issuer, "aud": audience, "sub": "u", "email": ownerEmail, "exp": time.Now().Add(-time.Minute).Unix()}),
		"no expiry":      fa.mint(t, jwt.MapClaims{"iss": fa.issuer, "aud": audience, "sub": "u", "email": ownerEmail}),
		"other user":     fa.mint(t, jwt.MapClaims{"iss": fa.issuer, "aud": audience, "sub": "u", "email": "intruder@example.com", "exp": exp}),
		"hs256":          hs256(t, jwt.MapClaims{"iss": fa.issuer, "aud": audience, "sub": "u", "email": ownerEmail, "exp": exp}),
		"alg none":       "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + jwtPart(`{"iss":"`+fa.issuer+`","aud":"`+audience+`","sub":"u","email":"`+ownerEmail+`"}`) + ".",
		"garbage":        "not-a-jwt",
	}
	for name, tok := range cases {
		b := h.browser()
		b.headers.Set(auth.AccessHeader, tok)
		if tok == "" {
			b.headers.Del(auth.AccessHeader)
		}
		if st, _ := b.do("POST", "/api/v1/auth/login", map[string]string{"password": ownerPassword, "code": h.code()}); st != 403 {
			t.Errorf("%s: login status %d, want 403", name, st)
		}
		if st, _ := b.do("GET", "/", nil); st != 403 {
			t.Errorf("%s: static status %d, want 403", name, st)
		}
		if _, st := b.dialTerm(); st != 403 {
			t.Errorf("%s: terminal upgrade %d, want 403", name, st)
		}
	}
	b := h.browser()
	if st, _ := b.do("GET", "/", nil); st != 200 {
		t.Fatalf("valid owner assertion rejected: %d", st)
	}
}

func hs256(t *testing.T, c jwt.MapClaims) string {
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func jwtPart(s string) string {
	return strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(b64(s)), "=")
}

func TestServicePrincipalCannotActAsOwner(t *testing.T) {
	h := newHarness(t, ModeAccess)
	svc := h.cli(serviceID)
	svc.headers.Set("Origin", h.http.URL)
	if st, _ := svc.do("POST", "/api/v1/auth/login", map[string]string{"password": ownerPassword, "code": h.code()}); st != 403 {
		t.Fatalf("service token reached owner login: %d", st)
	}
	owner := h.browser()
	owner.login()
	if st, _ := owner.do("POST", "/api/v1/cli/pair/start", map[string]string{"label": "x"}); st != 403 {
		t.Fatalf("owner assertion started CLI pairing: %d", st)
	}
	if st, _ := h.cli("svc-unknown.access").do("POST", "/api/v1/cli/pair/start", map[string]string{"label": "x"}); st != 403 {
		t.Fatalf("unlisted service token started pairing: %d", st)
	}
}

func TestServiceTokenAloneGrantsNothing(t *testing.T) {
	h := newHarness(t, ModeAccess)
	svc := h.cli(serviceID)
	if st, _ := svc.do("GET", "/api/v1/cli/hosts", nil); st != 401 {
		t.Fatalf("service token without device token listed hosts: %d", st)
	}
	if _, st := svc.dialTerm(); st != 403 {
		t.Fatalf("service token alone opened terminal upgrade: %d", st)
	}
	svc.headers.Set("Authorization", "Bearer ymd_forged")
	if st, _ := svc.do("GET", "/api/v1/cli/hosts", nil); st != 401 {
		t.Fatalf("forged device token accepted: %d", st)
	}
}

func TestDeviceTokenBoundToServicePrincipal(t *testing.T) {
	h := newHarness(t, ModeAccess)
	owner := h.browser()
	owner.login()
	cli, _ := h.pair(owner, serviceID, "laptop")
	if st, _ := cli.do("GET", "/api/v1/cli/hosts", nil); st != 200 {
		t.Fatalf("paired device: %d", st)
	}
	stolen := h.cli("svc-other.access")
	stolen.headers.Set("Authorization", cli.headers.Get("Authorization"))
	if st, _ := stolen.do("GET", "/api/v1/cli/hosts", nil); st != 401 {
		t.Fatalf("device token used with another service token: %d", st)
	}
	cli.headers.Del(auth.AccessHeader)
	if st, _ := cli.do("GET", "/api/v1/cli/hosts", nil); st != 403 {
		t.Fatalf("device token without Access assertion: %d", st)
	}
	// Owner-only APIs stay closed to devices.
	cli.headers.Set(auth.AccessHeader, h.access.service(t, serviceID))
	if st, _ := cli.do("GET", "/api/v1/hosts", nil); st != 403 {
		t.Fatalf("device reached owner host API: %d", st)
	}
}

func TestPairingPollBoundToStartingPrincipal(t *testing.T) {
	h := newHarness(t, ModeAccess)
	owner := h.browser()
	owner.login()
	cli := h.cli(serviceID)
	_, start := cli.do("POST", "/api/v1/cli/pair/start", map[string]string{"label": "laptop"})
	owner.do("POST", "/api/v1/pairings/approve", map[string]string{"userCode": start["userCode"].(string), "password": ownerPassword, "code": h.code()})
	other := h.cli("svc-other.access")
	if _, res := other.do("POST", "/api/v1/cli/pair/poll", map[string]string{"pollToken": start["pollToken"].(string)}); res["status"] != "expired" || res["deviceToken"] != nil {
		t.Fatalf("other principal collected token: %v", res)
	}
}

func TestPairingApprovalNeedsPasswordAndTOTPEveryTime(t *testing.T) {
	h := newHarness(t, ModeStandalone)
	owner := h.browser()
	owner.login()
	cli := h.cli("")
	_, start := cli.do("POST", "/api/v1/cli/pair/start", map[string]string{"label": "laptop"})
	code := start["userCode"].(string)
	if st, _ := owner.do("POST", "/api/v1/pairings/approve", map[string]string{"userCode": code, "password": ownerPassword, "code": "000000"}); st != 401 {
		t.Fatalf("approval without valid TOTP: %d", st)
	}
	if st, _ := h.browser().do("POST", "/api/v1/pairings/approve", map[string]string{"userCode": code, "password": ownerPassword, "code": h.code()}); st != 401 {
		t.Fatalf("approval without session: %d", st)
	}
	time.Sleep(2100 * time.Millisecond)
	if _, res := cli.do("POST", "/api/v1/cli/pair/poll", map[string]string{"pollToken": start["pollToken"].(string)}); res["status"] != "pending" {
		t.Fatalf("pairing not pending: %v", res)
	}
	if st, _ := owner.do("POST", "/api/v1/pairings/approve", map[string]string{"userCode": strings.ToLower(strings.ReplaceAll(code, "-", "")), "password": ownerPassword, "code": h.code()}); st != 204 {
		t.Fatalf("valid approval: %d", st)
	}
	time.Sleep(2100 * time.Millisecond)
	_, res := cli.do("POST", "/api/v1/cli/pair/poll", map[string]string{"pollToken": start["pollToken"].(string)})
	if res["status"] != "approved" {
		t.Fatalf("poll after approval: %v", res)
	}
	if _, again := cli.do("POST", "/api/v1/cli/pair/poll", map[string]string{"pollToken": start["pollToken"].(string)}); again["status"] != "expired" {
		t.Fatalf("token issued twice: %v", again)
	}
}

func TestDeviceExpiresAfter30Days(t *testing.T) {
	h := newHarness(t, ModeStandalone)
	owner := h.browser()
	owner.login()
	cli, _ := h.pair(owner, StandalonePrincipal, "laptop")
	h.store.SetClock(func() time.Time { return time.Now().Add(30*24*time.Hour - time.Minute) })
	if st, _ := cli.do("GET", "/api/v1/cli/hosts", nil); st != 200 {
		t.Fatalf("device rejected before expiry: %d", st)
	}
	h.store.SetClock(func() time.Time { return time.Now().Add(30*24*time.Hour + time.Second) })
	if st, _ := cli.do("GET", "/api/v1/cli/hosts", nil); st != 401 {
		t.Fatalf("device accepted after 30 days: %d", st)
	}
}

func TestReadAPIsNeverReturnSecrets(t *testing.T) {
	tgt := testutil.GoServer(t, testutil.GoServerOptions{})
	h := newHarness(t, ModeStandalone)
	owner := h.browser()
	owner.login()
	h.addHost(owner, "pw", tgt, passwordAuth(tgt))
	h.addHost(owner, "key", tgt, keyAuth(tgt))
	cli, _ := h.pair(owner, StandalonePrincipal, "laptop")
	_, ownerList := owner.raw("GET", "/api/v1/hosts", nil)
	_, cliList := cli.raw("GET", "/api/v1/cli/hosts", nil)
	for _, body := range []string{string(ownerList), string(cliList)} {
		for _, secret := range []string{tgt.Password, "PRIVATE KEY", "credential"} {
			if strings.Contains(body, secret) {
				t.Fatalf("read API leaked %q: %s", secret, body)
			}
		}
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestParallelGuessesCannotExceedBudget(t *testing.T) {
	h := newHarness(t, ModeStandalone)
	var wg sync.WaitGroup
	var evaluated atomic.Int32
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if st, _ := h.browser().do("POST", "/api/v1/auth/login", map[string]string{"password": "guess guess guess", "code": "123456"}); st == 401 {
				evaluated.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := evaluated.Load(); n > 5 {
		t.Fatalf("%d parallel guesses were evaluated, budget is 5", n)
	}
}
