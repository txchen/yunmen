// Package terminal bridges one authenticated WebSocket to one SSH PTY shell.
//
// Lifecycle: Opening -> Active -> Closed(reason). Terminal bytes are never
// interpreted. Output is flow-controlled by cumulative client acks; input is
// acked after it is written to the SSH channel.
package terminal

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/txchen/yunmen/internal/live"
	"github.com/txchen/yunmen/internal/protocol"
	"github.com/txchen/yunmen/internal/sshconn"
	"github.com/txchen/yunmen/internal/store"
	"golang.org/x/crypto/ssh"
)

type Deps struct {
	Store    *store.Store
	Registry *live.Registry
	Log      *slog.Logger

	OpenTimeout  time.Duration // waiting for the client's open message
	Heartbeat    time.Duration // WebSocket ping interval
	SlowConsumer time.Duration // max time without ack progress while output is pending
}

func (d Deps) withDefaults() Deps {
	if d.OpenTimeout == 0 {
		d.OpenTimeout = 10 * time.Second
	}
	if d.Heartbeat == 0 {
		d.Heartbeat = 25 * time.Second
	}
	if d.SlowConsumer == 0 {
		d.SlowConsumer = 60 * time.Second
	}
	return d
}

// Principal is the authenticated caller. Deadline is the earliest of the
// Yunmen credential expiry and the Access assertion expiry.
type Principal struct {
	Cred     live.Credential
	Deadline time.Time
}

type item struct {
	data  []byte
	ctrl  *protocol.Control
	final bool
}

type term struct {
	d      Deps
	conn   *websocket.Conn
	ctx    context.Context // cancelled when the terminal ends
	cancel context.CancelFunc
	// ioCtx outlives ctx until the end message is written: coder/websocket
	// closes the connection when a Read or Write context is cancelled.
	ioCtx    context.Context
	deadline time.Time
	lease    *live.Lease

	mu      sync.Mutex
	reason  protocol.EndReason
	message string
	session *ssh.Session
	// input carries client bytes to the stdin writer goroutine, so a blocked
	// SSH channel write never stops acks, pongs, resize or close.
	input chan []byte
	view  protocol.Viewport

	queue       chan item
	ackSignal   chan struct{}
	inputAcked  atomic.Int64
	inputQueued atomic.Int64

	flowMu   sync.Mutex
	sent     int64
	acked    int64
	progress chan struct{}
}

// Serve runs one terminal until it ends. It owns conn.
func Serve(parent context.Context, conn *websocket.Conn, p Principal, d Deps) {
	d = d.withDefaults()
	defer conn.CloseNow()
	conn.SetReadLimit(protocol.MaxPayload)

	openCtx, cancelOpen := context.WithTimeout(parent, d.OpenTimeout)
	typ, data, err := conn.Read(openCtx)
	cancelOpen()
	if err != nil {
		return
	}
	var open protocol.Control
	if typ == websocket.MessageText {
		open, err = protocol.ParseClient(data)
	}
	if typ != websocket.MessageText || err != nil || open.Type != protocol.TypeOpen {
		writeEnd(parent, conn, protocol.EndProtocolError, "first message must be a valid open control")
		return
	}
	view, _ := protocol.NewViewport(open.Cols, open.Rows)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	ioCtx, cancelIO := context.WithCancel(context.WithoutCancel(parent))
	defer cancelIO()
	t := &term{d: d, conn: conn, ctx: ctx, cancel: cancel, ioCtx: ioCtx, deadline: p.Deadline, view: view,
		queue: make(chan item, 8), input: make(chan []byte, inputFrames), ackSignal: make(chan struct{}, 1), progress: make(chan struct{})}

	lease, err := d.Registry.Register(p.Cred, open.HostID, live.KindTerminal, p.Deadline, t.end)
	if err != nil {
		writeEnd(parent, conn, live.Reason(err), err.Error())
		return
	}
	t.lease = lease
	defer lease.Release()

	writerDone := make(chan struct{})
	go func() { defer close(writerDone); t.writer() }()
	go t.reader()
	go t.heartbeat()

	started := time.Now()
	host, err := t.open(open.HostID, protocol.SanitizeTerm(open.Term))
	if err != nil {
		t.endWith(sshconn.ReasonOf(err), err.Error())
	} else {
		d.Log.Info("terminal ready", "host", host.Alias, "cred", credKind(p.Cred), "open_ms", time.Since(started).Milliseconds())
	}
	<-writerDone
	t.mu.Lock()
	reason := t.reason
	if t.session != nil {
		t.session.Close()
	}
	t.mu.Unlock()
	lease.Release()
	// The close handshake can wait on a slow peer; SSH is already released.
	conn.Close(websocket.StatusNormalClosure, "")
	d.Log.Info("terminal closed", "host", host.Alias, "reason", reason, "duration_s", int(time.Since(started).Seconds()))
}

func credKind(c live.Credential) string {
	s := string(c)
	for i := range s {
		if s[i] == ':' {
			return s[:i]
		}
	}
	return s
}

func writeEnd(ctx context.Context, conn *websocket.Conn, r protocol.EndReason, msg string) {
	wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn.Write(wctx, websocket.MessageText, protocol.Encode(protocol.Control{Type: protocol.TypeEnd, Reason: r, Message: msg}))
	conn.Close(websocket.StatusNormalClosure, "")
}

// end is the registry's EndFunc: idempotent, non-blocking, first reason wins.
func (t *term) end(r protocol.EndReason) { t.endWith(r, protocol.Describe(r)) }

func (t *term) endWith(r protocol.EndReason, msg string) {
	t.mu.Lock()
	if t.reason == "" {
		t.reason, t.message = r, msg
	}
	t.mu.Unlock()
	t.cancel()
}

func (t *term) open(hostID, termName string) (store.Host, error) {
	host, cred, err := t.d.Store.HostSnapshot(t.ctx, hostID)
	if errors.Is(err, store.ErrNotFound) {
		return host, &sshconn.Error{Reason: protocol.EndOpenFailed, Msg: "unknown host"}
	}
	if err != nil {
		return host, &sshconn.Error{Reason: protocol.EndOpenFailed, Msg: "could not load host"}
	}
	if cred.KeyID != "" {
		if err := t.lease.BindKey(cred.KeyID); err != nil {
			return host, &sshconn.Error{Reason: protocol.EndRevoked, Msg: err.Error()}
		}
	}
	client, err := sshconn.Dial(t.ctx, host, cred)
	if err != nil {
		return host, err
	}
	sess, err := client.NewSession()
	if err != nil {
		return host, &sshconn.Error{Reason: protocol.EndOpenFailed, Msg: "could not open ssh session"}
	}
	stdin, err1 := sess.StdinPipe()
	stdout, err2 := sess.StdoutPipe()
	stderr, err3 := sess.StderrPipe()
	if err := errors.Join(err1, err2, err3); err != nil {
		sess.Close()
		return host, &sshconn.Error{Reason: protocol.EndOpenFailed, Msg: "could not open ssh session"}
	}
	t.mu.Lock()
	view := t.view
	t.mu.Unlock()
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.IUTF8: 1, ssh.TTY_OP_ISPEED: 115200, ssh.TTY_OP_OSPEED: 115200}
	if err := sess.RequestPty(termName, view.Rows, view.Cols, modes); err != nil {
		sess.Close()
		return host, &sshconn.Error{Reason: protocol.EndOpenFailed, Msg: "target refused a pty"}
	}
	if err := sess.Shell(); err != nil {
		sess.Close()
		return host, &sshconn.Error{Reason: protocol.EndOpenFailed, Msg: "target refused a shell"}
	}
	t.mu.Lock()
	if t.ctx.Err() != nil {
		t.mu.Unlock()
		sess.Close()
		return host, t.ctx.Err()
	}
	t.session = sess
	go t.stdinWriter(stdin)
	// A resize that arrived while opening is applied now.
	if t.view != view {
		sess.WindowChange(t.view.Rows, t.view.Cols)
	}
	t.mu.Unlock()

	t.enqueue(item{ctrl: &protocol.Control{Type: protocol.TypeReady, SessionID: store.NewID(), ExpiresAt: t.deadline.UTC().Format(time.RFC3339)}})
	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() { defer pumps.Done(); t.pump(stdout) }()
	go func() { defer pumps.Done(); t.pump(stderr) }()
	go func() {
		pumps.Wait()
		end := protocol.Control{Type: protocol.TypeEnd, Reason: protocol.EndRemoteExit}
		var exitErr *ssh.ExitError
		switch err := sess.Wait(); {
		case err == nil:
			zero := 0
			end.ExitStatus = &zero
		case errors.As(err, &exitErr):
			if exitErr.Signal() != "" {
				end.Signal = exitErr.Signal()
			} else {
				st := exitErr.ExitStatus()
				end.ExitStatus = &st
			}
		}
		if t.ctx.Err() != nil {
			return
		}
		end.Message = protocol.Describe(protocol.EndRemoteExit)
		t.mu.Lock()
		if t.reason == "" {
			t.reason = protocol.EndRemoteExit
		}
		t.mu.Unlock()
		t.enqueue(item{ctrl: &end, final: true})
	}()
	return host, nil
}

func (t *term) enqueue(it item) bool {
	select {
	case t.queue <- it:
		return true
	case <-t.ctx.Done():
		return false
	}
}

// writer is the only goroutine that writes data frames to conn.
func (t *term) writer() {
	for {
		if t.ctx.Err() != nil {
			t.writeFinalEnd()
			return
		}
		select {
		case it := <-t.queue:
			var err error
			if it.ctrl != nil {
				err = t.write(websocket.MessageText, protocol.Encode(*it.ctrl))
			} else {
				err = t.write(websocket.MessageBinary, it.data)
			}
			if it.final {
				t.cancel()
				return
			}
			if err != nil {
				t.end(protocol.EndNetworkLost)
			}
		case <-t.ackSignal:
			ack := protocol.Control{Type: protocol.TypeAck, Bytes: t.inputAcked.Load()}
			if err := t.write(websocket.MessageText, protocol.Encode(ack)); err != nil {
				t.end(protocol.EndNetworkLost)
			}
		case <-t.ctx.Done():
			t.writeFinalEnd()
			return
		}
	}
}

func (t *term) write(typ websocket.MessageType, b []byte) error {
	ctx, cancel := context.WithTimeout(t.ioCtx, t.d.SlowConsumer)
	defer cancel()
	return t.conn.Write(ctx, typ, b)
}

func (t *term) writeFinalEnd() {
	t.mu.Lock()
	end := protocol.Control{Type: protocol.TypeEnd, Reason: t.reason, Message: t.message}
	t.mu.Unlock()
	// A remote-exit end may have been queued just as the context ended; prefer
	// it so the exit status is not lost.
	for drained := false; !drained; {
		select {
		case it := <-t.queue:
			if it.final && it.ctrl != nil && end.Reason == protocol.EndRemoteExit {
				end = *it.ctrl
			}
		default:
			drained = true
		}
	}
	ctx, cancel := context.WithTimeout(t.ioCtx, 2*time.Second)
	defer cancel()
	t.conn.Write(ctx, websocket.MessageText, protocol.Encode(end))
}

// pump copies one SSH output stream into the queue, respecting the window.
func (t *term) pump(r io.Reader) {
	buf := make([]byte, protocol.MaxPayload)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if !t.waitWindow(int64(n)) {
				return
			}
			if !t.enqueue(item{data: append([]byte(nil), buf[:n]...)}) {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (t *term) waitWindow(n int64) bool {
	var stall *time.Timer
	defer func() {
		if stall != nil {
			stall.Stop()
		}
	}()
	for {
		t.flowMu.Lock()
		if t.sent-t.acked+n <= protocol.OutputWindow {
			t.sent += n
			t.flowMu.Unlock()
			return true
		}
		progress := t.progress
		t.flowMu.Unlock()
		if stall == nil {
			stall = time.NewTimer(t.d.SlowConsumer)
		}
		select {
		case <-progress:
			stall.Stop()
			stall = nil
		case <-stall.C:
			t.end(protocol.EndSlowConsumer)
			return false
		case <-t.ctx.Done():
			return false
		}
	}
}

func (t *term) ack(bytes int64) bool {
	t.flowMu.Lock()
	defer t.flowMu.Unlock()
	if bytes < t.acked || bytes > t.sent {
		return false
	}
	if bytes > t.acked {
		t.acked = bytes
		close(t.progress)
		t.progress = make(chan struct{})
	}
	return true
}

func (t *term) reader() {
	for {
		typ, data, err := t.conn.Read(t.ioCtx)
		if err != nil {
			switch websocket.CloseStatus(err) {
			case websocket.StatusNormalClosure, websocket.StatusGoingAway:
				t.end(protocol.EndClientClose)
			default:
				t.end(protocol.EndNetworkLost)
			}
			return
		}
		if typ == websocket.MessageBinary {
			t.mu.Lock()
			started := t.session != nil
			t.mu.Unlock()
			if !started {
				t.endWith(protocol.EndProtocolError, "input before ready")
				return
			}
			if t.inputQueued.Add(int64(len(data))) > inputMaxBytes {
				t.endWith(protocol.EndProtocolError, "client exceeded the input window")
				return
			}
			select {
			case t.input <- data:
			default:
				t.endWith(protocol.EndProtocolError, "client exceeded the input window")
				return
			}
			continue
		}
		c, err := protocol.ParseClient(data)
		if err != nil {
			t.endWith(protocol.EndProtocolError, err.Error())
			return
		}
		switch c.Type {
		case protocol.TypeResize:
			v, _ := protocol.NewViewport(c.Cols, c.Rows)
			t.mu.Lock()
			t.view = v
			if t.session != nil {
				t.session.WindowChange(v.Rows, v.Cols)
			}
			t.mu.Unlock()
		case protocol.TypeAck:
			if !t.ack(c.Bytes) {
				t.endWith(protocol.EndProtocolError, "invalid ack")
				return
			}
		case protocol.TypeClose:
			t.end(protocol.EndClientClose)
			return
		default:
			t.endWith(protocol.EndProtocolError, "unexpected control "+string(c.Type))
			return
		}
	}
}

// Queued client input is bounded by bytes (a client honoring InputWindow
// never exceeds it) and by frames, since typing sends one-byte frames.
const (
	inputFrames   = 4096
	inputMaxBytes = protocol.InputWindow + protocol.MaxPayload
)

func (t *term) stdinWriter(stdin io.Writer) {
	for {
		select {
		case data := <-t.input:
			n, err := stdin.Write(data)
			t.inputQueued.Add(-int64(len(data)))
			if err != nil {
				t.end(protocol.EndRemoteExit)
				return
			}
			t.inputAcked.Add(int64(n))
			select {
			case t.ackSignal <- struct{}{}:
			default:
			}
		case <-t.ctx.Done():
			return
		}
	}
}

func (t *term) heartbeat() {
	tick := time.NewTicker(t.d.Heartbeat)
	defer tick.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-tick.C:
			pctx, cancel := context.WithTimeout(t.ioCtx, t.d.Heartbeat)
			err := t.conn.Ping(pctx)
			cancel()
			if err != nil && t.ctx.Err() == nil {
				t.end(protocol.EndNetworkLost)
				return
			}
		}
	}
}
