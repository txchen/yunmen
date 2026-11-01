package server

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
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
	// inputSent counts input bytes sent; senders may be different goroutines.
	inputSent atomic.Int64

	mu         sync.Mutex // guards out, acked, end, closed once the reader runs
	closed     bool
	readerOnce sync.Once
	notify     chan struct{}
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
		tm.inputSent.Add(int64(n))
		b = b[n:]
	}
}

func (tm *term) consume(data []byte) {
	tm.out.Write(data)
	tm.acked += int64(len(data))
	tm.control(protocol.Control{Type: protocol.TypeAck, Bytes: tm.acked})
}

// startReader reads the socket in one goroutine for the rest of the test.
// coder/websocket closes the connection when a Read context expires, so
// waits must poll this reader instead of reading with a timeout.
func (tm *term) startReader() {
	tm.readerOnce.Do(func() {
		tm.notify = make(chan struct{}, 1)
		go func() {
			for {
				typ, data, err := tm.conn.Read(context.Background())
				tm.mu.Lock()
				switch {
				case err != nil:
					tm.closed = true
				case typ == websocket.MessageBinary:
					tm.consume(data)
				default:
					ctl, _ := protocol.ParseServer(data)
					switch ctl.Type {
					case protocol.TypeEnd:
						tm.end = &ctl
					case protocol.TypeAck:
						tm.inputAcked.Store(ctl.Bytes)
					}
				}
				tm.mu.Unlock()
				select {
				case tm.notify <- struct{}{}:
				default:
				}
				if err != nil {
					return
				}
			}
		}()
	})
}

// output returns a copy of all terminal output received so far.
func (tm *term) output() []byte {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return bytes.Clone(tm.out.Bytes())
}

// readUntil waits until pred holds over all output so far, or the terminal
// ends or the timeout passes. The connection stays open either way.
func (tm *term) readUntil(timeout time.Duration, pred func([]byte) bool) bool {
	tm.startReader()
	deadline := time.After(timeout)
	for {
		tm.mu.Lock()
		ok, done := pred(tm.out.Bytes()), tm.end != nil || tm.closed
		tm.mu.Unlock()
		if ok {
			return true
		}
		if done {
			return false
		}
		select {
		case <-tm.notify:
		case <-deadline:
			return false
		}
	}
}

func (tm *term) endState() *protocol.Control {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.end
}

func (tm *term) expect(s string) {
	tm.t.Helper()
	if !tm.readUntil(15*time.Second, func(b []byte) bool { return bytes.Contains(b, []byte(s)) }) {
		tm.t.Fatalf("did not see %q; end=%+v; output tail: %q", s, tm.endState(), tail(string(tm.output())))
	}
}

// waitEnd returns the end control (failing if none arrives in time).
func (tm *term) waitEnd(timeout time.Duration) protocol.Control {
	tm.t.Helper()
	tm.readUntil(timeout, func([]byte) bool { return false })
	end := tm.endState()
	if end == nil {
		tm.t.Fatalf("terminal did not end; output tail: %q", tail(string(tm.output())))
	}
	return *end
}

func tail(s string) string {
	if len(s) > 400 {
		return s[len(s)-400:]
	}
	return strings.ToValidUTF8(s, "?")
}
