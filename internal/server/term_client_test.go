package server

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/txchen/yunmen/internal/protocol"
)

// term is a test terminal client speaking yunmen.term.v1 and acking output.
type term struct {
	t     *testing.T
	conn  *websocket.Conn
	out   bytes.Buffer
	acked int64
	end   *protocol.Control
	ready protocol.Control
	// inputAcked is the server's cumulative input ack, updated while reading.
	inputAcked atomic.Int64
}

func (c *client) wsHeaders() http.Header {
	h := http.Header{}
	for k, v := range c.headers {
		h[k] = v
	}
	if c.jar != nil {
		u, _ := url.Parse(c.h.http.URL)
		for _, ck := range c.jar.Cookies(u) {
			h.Add("Cookie", ck.Name+"="+ck.Value)
		}
	}
	return h
}

// dialTerm upgrades and returns the HTTP status on failure (0 on success).
func (c *client) dialTerm() (*websocket.Conn, int) {
	conn, resp, err := websocket.Dial(context.Background(), wsURL(c.h), &websocket.DialOptions{
		HTTPHeader: c.wsHeaders(), Subprotocols: []string{protocol.Subprotocol}})
	if err != nil {
		if resp != nil {
			return nil, resp.StatusCode
		}
		c.h.t.Fatal(err)
	}
	conn.SetReadLimit(1 << 20)
	return conn, 0
}

// openTerm opens a shell on hostID and waits for ready.
func (c *client) openTerm(hostID string) *term {
	c.h.t.Helper()
	conn, st := c.dialTerm()
	if st != 0 {
		c.h.t.Fatalf("terminal upgrade rejected: %d", st)
	}
	tm := &term{t: c.h.t, conn: conn}
	c.h.t.Cleanup(func() { conn.CloseNow() })
	tm.control(protocol.Control{Type: protocol.TypeOpen, HostID: hostID, Cols: 80, Rows: 24, Term: "xterm-256color"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			c.h.t.Fatalf("waiting for ready: %v", err)
		}
		if typ == websocket.MessageText {
			ctl, _ := protocol.ParseServer(data)
			if ctl.Type == protocol.TypeReady {
				tm.ready = ctl
				return tm
			}
			if ctl.Type == protocol.TypeEnd {
				tm.end = &ctl
				return tm
			}
			continue
		}
		tm.consume(data)
	}
}

func (tm *term) control(c protocol.Control) {
	tm.conn.Write(context.Background(), websocket.MessageText, protocol.Encode(c))
}

func (tm *term) send(b []byte) {
	for len(b) > 0 {
		n := min(len(b), protocol.MaxPayload)
		if err := tm.conn.Write(context.Background(), websocket.MessageBinary, b[:n]); err != nil {
			tm.t.Fatalf("send: %v", err)
		}
		b = b[n:]
	}
}

func (tm *term) consume(data []byte) {
	tm.out.Write(data)
	tm.acked += int64(len(data))
	tm.control(protocol.Control{Type: protocol.TypeAck, Bytes: tm.acked})
}

// readUntil reads until pred holds over all output so far, or the terminal ends.
func (tm *term) readUntil(timeout time.Duration, pred func([]byte) bool) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for !pred(tm.out.Bytes()) {
		if tm.end != nil {
			return false
		}
		typ, data, err := tm.conn.Read(ctx)
		if err != nil {
			return false
		}
		if typ == websocket.MessageBinary {
			tm.consume(data)
			continue
		}
		ctl, _ := protocol.ParseServer(data)
		switch ctl.Type {
		case protocol.TypeEnd:
			tm.end = &ctl
		case protocol.TypeAck:
			tm.inputAcked.Store(ctl.Bytes)
		}
	}
	return true
}

func (tm *term) expect(s string) {
	tm.t.Helper()
	if !tm.readUntil(15*time.Second, func(b []byte) bool { return bytes.Contains(b, []byte(s)) }) {
		tm.t.Fatalf("did not see %q; end=%+v; output tail: %q", s, tm.end, tail(tm.out.String()))
	}
}

// waitEnd returns the end control (failing if none arrives in time).
func (tm *term) waitEnd(timeout time.Duration) protocol.Control {
	tm.t.Helper()
	tm.readUntil(timeout, func([]byte) bool { return false })
	if tm.end == nil {
		tm.t.Fatalf("terminal did not end; output tail: %q", tail(tm.out.String()))
	}
	return *tm.end
}

func tail(s string) string {
	if len(s) > 400 {
		return s[len(s)-400:]
	}
	return strings.ToValidUTF8(s, "?")
}
