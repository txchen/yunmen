package server

import (
	"fmt"
	"testing"
)

func guess(c *client) int {
	st, _ := c.do("POST", "/api/v1/auth/login", map[string]string{"password": "wrong wrong wrong", "code": "123456"})
	return st
}

// With YUNMEN_CLIENT_IP_HEADER set, one visitor's failures do not lock out
// another visitor arriving through the same tunnel.
func TestClientIPHeaderSeparatesVisitors(t *testing.T) {
	h := newHarness(t, ModeStandalone)
	h.srv.cfg.ClientIPHeader = "Cf-Connecting-Ip"
	attacker := h.browser()
	attacker.headers.Set("Cf-Connecting-IP", "203.0.113.7")
	for i := 0; i < 5; i++ {
		guess(attacker)
	}
	if st := guess(attacker); st != 429 {
		t.Fatalf("attacker not limited: %d", st)
	}
	owner := h.browser()
	owner.headers.Set("Cf-Connecting-IP", "198.51.100.20")
	owner.login()
}

// Without the setting the header is ignored, so a client cannot escape the
// limit by sending a fresh address with every guess.
func TestClientIPHeaderIgnoredUnlessConfigured(t *testing.T) {
	h := newHarness(t, ModeStandalone)
	for i := 0; i < 5; i++ {
		c := h.browser()
		c.headers.Set("Cf-Connecting-IP", fmt.Sprintf("203.0.113.%d", i))
		guess(c)
	}
	c := h.browser()
	c.headers.Set("Cf-Connecting-IP", "203.0.113.99")
	if st, _ := c.do("POST", "/api/v1/auth/login", map[string]string{"password": ownerPassword, "code": h.code()}); st != 429 {
		t.Fatalf("spoofed header escaped the limit: %d", st)
	}
}

func TestClientIPHeaderConfig(t *testing.T) {
	env := func(header string) func(string) string {
		values := map[string]string{"YUNMEN_MODE": "standalone", "YUNMEN_PUBLIC_ORIGIN": "https://y.example", "YUNMEN_CLIENT_IP_HEADER": header}
		return func(k string) string { return values[k] }
	}
	if c, err := LoadConfig(env("cf-connecting-ip")); err != nil || c.ClientIPHeader != "Cf-Connecting-Ip" {
		t.Fatalf("valid header: %q %v", c.ClientIPHeader, err)
	}
	if _, err := LoadConfig(env("Bad Header:")); err == nil {
		t.Fatal("invalid header name accepted")
	}
	if c, _ := LoadConfig(env("")); c.ClientIPHeader != "" {
		t.Fatal("header trusted without configuration")
	}
}
