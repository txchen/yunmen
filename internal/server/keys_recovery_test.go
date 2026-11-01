package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/txchen/yunmen/internal/auth"
	"github.com/txchen/yunmen/internal/protocol"
	"golang.org/x/crypto/ssh"
)

func (h *harness) addHostWithAuth(owner *client, alias string, address string, port int, user string, authBody map[string]any) (int, map[string]any) {
	h.t.Helper()
	_, probe := owner.do("POST", "/api/v1/hosts/probe", map[string]any{"address": address, "port": port})
	return owner.do("POST", "/api/v1/hosts", map[string]any{"alias": alias, "address": address, "port": port,
		"username": user, "auth": authBody, "observationId": probe["observationId"]})
}

// A key generated on the gateway is installed on the target by its public
// line only, then shared by two hosts. Deleting it is refused while hosts
// use it, and it ends sessions still authenticated with it.
func TestKeyLibraryGenerateShareAndDelete(t *testing.T) {
	h, owner, _, tgt := sshdHost(t, ModeStandalone)
	st, gen := owner.do("POST", "/api/v1/keys", map[string]any{"label": "gateway key", "generate": true})
	if st != 201 || !strings.HasPrefix(gen["publicKey"].(string), "ssh-ed25519 ") {
		t.Fatalf("generate: %d %v", st, gen)
	}
	if body := string(mustRaw(t, owner, "/api/v1/keys")); strings.Contains(body, "PRIVATE") {
		t.Fatal("key list leaked private material")
	}
	f, _ := os.OpenFile(tgt.AuthorizedKeys, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(gen["publicKey"].(string) + "\n")
	f.Close()

	keyID := gen["id"].(string)
	ids := map[string]string{}
	for _, alias := range []string{"g1", "g2"} {
		st, res := h.addHostWithAuth(owner, alias, tgt.Address, tgt.Port, tgt.Username, map[string]any{"kind": "key", "keyId": keyID})
		if st != 201 || res["host"].(map[string]any)["keyLabel"] != "gateway key" {
			t.Fatalf("host %s with library key: %d %v", alias, st, res)
		}
		ids[alias] = res["host"].(map[string]any)["id"].(string)
	}
	st, del := owner.do("DELETE", "/api/v1/keys/"+keyID, nil)
	if st != 409 || len(del["usedBy"].([]any)) != 2 {
		t.Fatalf("delete used key: %d %v", st, del)
	}

	open := owner.openTerm(ids["g2"])
	open.send([]byte("echo via-$((1+2))\r"))
	open.expect("via-3")

	// g2 moves to another key; its open terminal still uses the generated one.
	host, _ := h.store.GetHost(context.Background(), ids["g2"])
	st, res := owner.do("PUT", "/api/v1/hosts/"+ids["g2"], map[string]any{"alias": "g2", "address": tgt.Address, "port": tgt.Port,
		"username": tgt.Username, "revision": host.Revision, "auth": map[string]any{"kind": "key", "privateKey": string(tgt.PrivateKey)}})
	if st != 200 {
		t.Fatalf("switch key: %d %v", st, res)
	}
	owner.do("DELETE", "/api/v1/hosts/"+ids["g1"], nil)
	if st, _ := owner.do("DELETE", "/api/v1/keys/"+keyID, nil); st != 204 {
		t.Fatalf("delete unused key: %d", st)
	}
	if end := open.waitEnd(5 * time.Second); end.Reason != protocol.EndRevoked {
		t.Fatalf("terminal using the deleted key: %+v", end)
	}
	fresh := owner.openTerm(ids["g2"])
	fresh.send([]byte("echo new-$((2+2))\r"))
	fresh.expect("new-4")
}

func TestInlineImportReusesLibraryKey(t *testing.T) {
	h, owner, _, tgt := sshdHost(t, ModeStandalone)
	h.addHost(owner, "second", tgt, keyAuth(tgt))
	_, keys := owner.raw("GET", "/api/v1/keys", nil)
	if n := strings.Count(string(keys), `"fingerprint"`); n != 1 || !strings.Contains(string(keys), `"usedBy":["box","second"]`) {
		t.Fatalf("library after two imports of one key: %s", keys)
	}
}

func mustRaw(t *testing.T, c *client, path string) []byte {
	st, b := c.raw("GET", path, nil)
	if st != 200 {
		t.Fatalf("GET %s: %d", path, st)
	}
	return b
}

func TestRecoveryCodeReplacesAuthenticator(t *testing.T) {
	h, owner, id, _ := sshdHost(t, ModeStandalone)
	codes, _ := h.store.ReplaceRecoveryCodes(context.Background())
	cli, _ := h.pair(owner, StandalonePrincipal, "laptop")
	term := cli.openTerm(id)

	anon := h.browser()
	if st, _ := anon.do("POST", "/api/v1/auth/recovery/start", map[string]string{"password": ownerPassword, "recoveryCode": "AAAAA-AAAAA"}); st != 401 {
		t.Fatalf("wrong recovery code: %d", st)
	}
	if st, _ := anon.do("POST", "/api/v1/auth/recovery/start", map[string]string{"password": "wrong password!!", "recoveryCode": codes[0]}); st != 401 {
		t.Fatalf("wrong password: %d", st)
	}
	st, ch := anon.do("POST", "/api/v1/auth/recovery/start", map[string]string{"password": ownerPassword, "recoveryCode": strings.ToLower(codes[0])})
	if st != 200 {
		t.Fatalf("start: %d %v", st, ch)
	}
	if st, _ := owner.do("GET", "/api/v1/hosts", nil); st != 200 {
		t.Fatal("starting recovery must not revoke anything yet")
	}
	newSecret, _ := decodeBase32(ch["secret"].(string))
	if st, _ := anon.do("POST", "/api/v1/auth/recovery/finish", map[string]string{"challengeId": ch["challengeId"].(string), "code": "000000"}); st != 401 {
		t.Fatalf("wrong new code: %d", st)
	}
	if st, _ := anon.do("POST", "/api/v1/auth/recovery/finish", map[string]string{"challengeId": ch["challengeId"].(string),
		"code": auth.TOTPCode(newSecret, h.now())}); st != 204 {
		t.Fatalf("finish: %d", st)
	}

	if st, _ := owner.do("GET", "/api/v1/hosts", nil); st != 401 {
		t.Fatalf("old browser session survived recovery: %d", st)
	}
	if end := term.waitEnd(5 * time.Second); end.Reason != protocol.EndRevoked {
		t.Fatalf("CLI terminal after recovery: %+v", end)
	}
	if st, _ := h.browser().do("POST", "/api/v1/auth/login", map[string]string{"password": ownerPassword, "code": h.code()}); st != 401 {
		t.Fatalf("old authenticator still logs in: %d", st)
	}
	h.totp = newSecret
	fresh := h.browser()
	fresh.login()
	if st, _ := anon.do("POST", "/api/v1/auth/recovery/start", map[string]string{"password": ownerPassword, "recoveryCode": codes[0]}); st != 401 {
		t.Fatalf("used recovery code accepted again: %d", st)
	}
	_, sess := fresh.do("GET", "/api/v1/auth/session", nil)
	if sess["recoveryCodesRemaining"].(float64) != 9 {
		t.Fatalf("remaining: %v", sess)
	}
	// Five deliberate failures above used up this client's login budget.
	h.srv.perClient = newLimiter(5, 5*time.Minute)
	st, regen := fresh.do("POST", "/api/v1/auth/recovery-codes", map[string]string{"password": ownerPassword, "code": h.code()})
	if st != 200 || len(regen["codes"].([]any)) != 10 {
		t.Fatalf("regenerate: %d %v", st, regen)
	}
	if st, _ := anon.do("POST", "/api/v1/auth/recovery/start", map[string]string{"password": ownerPassword, "recoveryCode": codes[1]}); st != 401 {
		t.Fatalf("old code after regeneration: %d", st)
	}
}

func decodeBase32(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// A save that fails after the connection test must not leave a newly
// imported key behind in the library.
func TestFailedHostSaveLeavesNoImportedKey(t *testing.T) {
	h, owner, _, tgt := sshdHost(t, ModeStandalone)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	signer, _ := ssh.NewSignerFromKey(priv)
	f, _ := os.OpenFile(tgt.AuthorizedKeys, os.O_APPEND|os.O_WRONLY, 0o600)
	f.Write(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	f.Close()
	st, res := h.addHostWithAuth(owner, "box", tgt.Address, tgt.Port, tgt.Username, map[string]any{"kind": "key", "privateKey": string(pem.EncodeToMemory(block))})
	if st != 409 {
		t.Fatalf("duplicate alias: %d %v", st, res)
	}
	if body := mustRaw(t, owner, "/api/v1/keys"); strings.Count(string(body), `"fingerprint"`) != 1 {
		t.Fatalf("library after failed save: %s", body)
	}
}
