package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/txchen/yunmen/internal/auth"
	"github.com/txchen/yunmen/internal/cli"
	"github.com/txchen/yunmen/internal/protocol"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// The real CLI client code (not the test client) drives a shell through the
// gateway: resize, Ctrl-C, remote exit status.
func TestCLIClientEndToEnd(t *testing.T) {
	h, owner, id, _ := sshdHost(t, ModeAccess)
	device, _ := h.pair(owner, serviceID, "laptop")
	gw, _ := url.Parse(h.http.URL)
	c := cli.NewClient(gw, cli.Secrets{DeviceToken: strings.TrimPrefix(device.headers.Get("Authorization"), "Bearer ")})
	// Cloudflare would mint this from the Client ID/Secret; the fake does it here.
	c.HTTP.Transport = headerTransport{auth.AccessHeader: h.access.service(t, serviceID)}

	hosts, err := c.Hosts(context.Background())
	if err != nil || len(hosts) != 1 || hosts[0].Alias != "box" {
		t.Fatalf("hosts: %v %v", hosts, err)
	}
	conn, err := c.DialTerminal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	inR, inW := io.Pipe()
	out := &syncBuf{}
	resize := make(chan struct{}, 1)
	var mu sync.Mutex
	cols, rows := 100, 30
	size := func() (int, int) { mu.Lock(); defer mu.Unlock(); return cols, rows }
	done := make(chan cli.Outcome, 1)
	go func() {
		done <- cli.RunTerminal(context.Background(), conn, id, cli.IO{In: inR, Out: out, Size: size, Resize: resize, Term: "screen-256color"})
	}()

	waitFor := func(s string) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for !strings.Contains(out.String(), s) {
			if time.Now().After(deadline) {
				t.Fatalf("did not see %q in %q", s, tail(out.String()))
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	inW.Write([]byte("echo term=$TERM; stty size\r"))
	waitFor("term=screen-256color")
	waitFor("30 100")
	mu.Lock()
	cols, rows = 120, 40
	mu.Unlock()
	resize <- struct{}{}
	time.Sleep(200 * time.Millisecond)
	inW.Write([]byte("stty size\r"))
	waitFor("40 120")
	inW.Write([]byte("sleep 20\r"))
	time.Sleep(300 * time.Millisecond)
	inW.Write([]byte{0x03})
	time.Sleep(300 * time.Millisecond)
	inW.Write([]byte("exit 3\r"))
	select {
	case o := <-done:
		if o.Reason != protocol.EndRemoteExit || o.ExitCode() != 3 {
			t.Fatalf("outcome %+v", o)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("CLI session did not end")
	}
}

type headerTransport map[string]string

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(r)
}
