package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/txchen/yunmen/internal/protocol"
	"golang.org/x/term"
)

// Outcome is how a terminal ended, from the client's point of view.
type Outcome struct {
	Reason     protocol.EndReason
	Message    string
	ExitStatus *int
	Signal     string
	Ready      bool
}

// ExitCode follows ssh: the remote status when known, 255 otherwise.
func (o Outcome) ExitCode() int {
	if o.Reason == protocol.EndRemoteExit && o.ExitStatus != nil {
		return *o.ExitStatus
	}
	if o.Reason == protocol.EndClientClose {
		return 0
	}
	return 255
}

// IO abstracts the local terminal so tests can drive a session without a TTY.
type IO struct {
	In     io.Reader
	Out    io.Writer
	Size   func() (cols, rows int)
	Resize <-chan struct{}
	Term   string
}

const heartbeat = 25 * time.Second

// Dial opens the terminal WebSocket with both credential layers.
func (c *Client) DialTerminal(ctx context.Context) (*websocket.Conn, error) {
	u := *c.Gateway
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = protocol.Path
	h := http.Header{}
	c.headers(h)
	conn, resp, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{
		HTTPClient:   c.HTTP,
		HTTPHeader:   h,
		Subprotocols: []string{protocol.Subprotocol},
	})
	if err != nil {
		if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
			return nil, describeHTTPError(resp)
		}
		return nil, fmt.Errorf("cannot open terminal connection to %s: %w", c.Gateway.Host, err)
	}
	if conn.Subprotocol() != protocol.Subprotocol {
		conn.CloseNow()
		return nil, errors.New("gateway does not speak " + protocol.Subprotocol + "; upgrade the CLI or the server")
	}
	conn.SetReadLimit(protocol.MaxPayload + protocol.MaxControl)
	return conn, nil
}

// escape implements ssh-style "Enter ~ ." local disconnect. It passes every
// other byte through unchanged, including Ctrl-C.
type escape struct {
	atLineStart bool
	pendingT    bool
}

// filter returns bytes to send and whether the user asked to disconnect.
func (e *escape) filter(in []byte) ([]byte, bool) {
	out := make([]byte, 0, len(in)+1)
	for _, b := range in {
		if e.pendingT {
			e.pendingT = false
			switch b {
			case '.':
				return out, true
			case '~':
				out = append(out, '~')
				e.atLineStart = false
				continue
			default:
				out = append(out, '~')
			}
		}
		if b == '~' && e.atLineStart {
			e.pendingT = true
			continue
		}
		out = append(out, b)
		e.atLineStart = b == '\r' || b == '\n'
	}
	return out, false
}

// inputWindow blocks writers while too many input bytes are unacknowledged.
type inputWindow struct {
	mu    sync.Mutex
	cond  *sync.Cond
	sent  int64
	acked int64
	done  bool
}

func newInputWindow() *inputWindow {
	w := &inputWindow{}
	w.cond = sync.NewCond(&w.mu)
	return w
}

func (w *inputWindow) reserve(n int64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for !w.done && w.sent-w.acked+n > protocol.InputWindow && w.sent > w.acked {
		w.cond.Wait()
	}
	w.sent += n
	return !w.done
}

func (w *inputWindow) ack(n int64) {
	w.mu.Lock()
	if n > w.acked {
		w.acked = n
	}
	w.mu.Unlock()
	w.cond.Broadcast()
}

func (w *inputWindow) close() {
	w.mu.Lock()
	w.done = true
	w.mu.Unlock()
	w.cond.Broadcast()
}

// RunTerminal attaches local IO to a remote shell until it ends. It does not
// touch terminal modes; the caller owns raw mode.
func RunTerminal(ctx context.Context, conn *websocket.Conn, hostID string, tio IO) Outcome {
	defer conn.CloseNow()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var mu sync.Mutex
	out := Outcome{}
	finish := func(o Outcome) {
		mu.Lock()
		if out.Reason == "" {
			ready := out.Ready
			out = o
			out.Ready = out.Ready || ready
		}
		mu.Unlock()
		cancel()
	}
	send := func(c protocol.Control) error {
		wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
		defer wcancel()
		return conn.Write(wctx, websocket.MessageText, protocol.Encode(c))
	}

	cols, rows := tio.Size()
	if err := send(protocol.Control{Type: protocol.TypeOpen, HostID: hostID, Cols: cols, Rows: rows, Term: protocol.SanitizeTerm(tio.Term)}); err != nil {
		return Outcome{Reason: protocol.EndNetworkLost, Message: "could not start terminal: " + err.Error()}
	}

	ready := make(chan struct{})
	var readyOnce sync.Once
	window := newInputWindow()
	defer window.close()

	go func() { // reader: output bytes and server controls
		var rendered int64
		for {
			typ, data, err := conn.Read(ctx)
			if err != nil {
				finish(Outcome{Reason: protocol.EndNetworkLost, Message: protocol.Describe(protocol.EndNetworkLost)})
				return
			}
			if typ == websocket.MessageBinary {
				if _, err := tio.Out.Write(data); err != nil {
					finish(Outcome{Reason: protocol.EndClientClose, Message: "local output failed"})
					return
				}
				rendered += int64(len(data))
				if err := send(protocol.Control{Type: protocol.TypeAck, Bytes: rendered}); err != nil {
					finish(Outcome{Reason: protocol.EndNetworkLost, Message: protocol.Describe(protocol.EndNetworkLost)})
					return
				}
				continue
			}
			c, err := protocol.ParseServer(data)
			if err != nil {
				finish(Outcome{Reason: protocol.EndProtocolError, Message: "unexpected message from gateway"})
				return
			}
			switch c.Type {
			case protocol.TypeReady:
				mu.Lock()
				out.Ready = true
				mu.Unlock()
				readyOnce.Do(func() { close(ready) })
			case protocol.TypeAck:
				window.ack(c.Bytes)
			case protocol.TypeEnd:
				finish(Outcome{Reason: c.Reason, Message: c.Message, ExitStatus: c.ExitStatus, Signal: c.Signal})
				return
			}
		}
	}()

	go func() { // client-side liveness check, independent of output
		t := time.NewTicker(heartbeat)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				pctx, pcancel := context.WithTimeout(ctx, heartbeat)
				err := conn.Ping(pctx)
				pcancel()
				if err != nil && ctx.Err() == nil {
					finish(Outcome{Reason: protocol.EndNetworkLost, Message: "gateway stopped responding"})
					return
				}
			}
		}
	}()

	go func() { // resize
		last := [2]int{cols, rows}
		for {
			select {
			case <-ctx.Done():
				return
			case <-tio.Resize:
				c, r := tio.Size()
				if [2]int{c, r} == last {
					continue
				}
				last = [2]int{c, r}
				if send(protocol.Control{Type: protocol.TypeResize, Cols: c, Rows: r}) != nil {
					return
				}
			}
		}
	}()

	go func() { // input: raw bytes, Ctrl-C included, after ready
		select {
		case <-ready:
		case <-ctx.Done():
			return
		}
		esc := &escape{atLineStart: true}
		buf := make([]byte, protocol.MaxPayload)
		for {
			n, err := tio.In.Read(buf)
			if n > 0 {
				data, quit := esc.filter(buf[:n])
				if len(data) > 0 {
					if !window.reserve(int64(len(data))) {
						return
					}
					wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
					werr := conn.Write(wctx, websocket.MessageBinary, data)
					wcancel()
					if werr != nil {
						return
					}
				}
				if quit {
					send(protocol.Control{Type: protocol.TypeClose})
					finish(Outcome{Reason: protocol.EndClientClose, Message: "disconnected (~.)"})
					return
				}
			}
			if err != nil {
				// Local stdin closed (EOF): ask the gateway to end politely.
				send(protocol.Control{Type: protocol.TypeClose})
				return
			}
		}
	}()

	<-ctx.Done()
	conn.Close(websocket.StatusNormalClosure, "")
	mu.Lock()
	defer mu.Unlock()
	if out.Reason == "" {
		out.Reason, out.Message = protocol.EndClientClose, "interrupted"
	}
	return out
}

// resetModes undoes input modes a remote program may have left enabled when
// the connection dropped mid-session. The screen contents are left alone.
const resetModes = "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?1l\x1b>\x1b[?25h\x1b[0m"

// Interactive runs RunTerminal on the process TTY with raw mode, restoring
// the terminal on every exit path including handled signals and panics.
func Interactive(ctx context.Context, conn *websocket.Conn, hostID string) (o Outcome, err error) {
	inFd, outFd := int(os.Stdin.Fd()), int(os.Stdout.Fd())
	if !term.IsTerminal(inFd) || !term.IsTerminal(outFd) {
		conn.CloseNow()
		return Outcome{}, errors.New("yunmen connect needs an interactive terminal (stdin and stdout must be a TTY)")
	}
	state, err := term.MakeRaw(inFd)
	if err != nil {
		conn.CloseNow()
		return Outcome{}, fmt.Errorf("cannot enter raw mode: %w", err)
	}
	restoreOutput := prepareOutput(os.Stdout)
	var restoreOnce sync.Once
	restore := func() {
		restoreOnce.Do(func() {
			term.Restore(inFd, state)
			restoreOutput()
		})
	}
	defer restore()
	defer func() {
		if p := recover(); p != nil {
			restore()
			panic(p)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP, os.Interrupt)
	defer signal.Stop(sigs)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-sigs:
			cancel()
		case <-ctx.Done():
		}
	}()

	resize, stopResize := watchResize()
	defer stopResize()
	size := func() (int, int) {
		c, r, err := term.GetSize(outFd)
		if err != nil || c <= 0 || r <= 0 {
			return 80, 24
		}
		return min(c, protocol.MaxDimension), min(r, protocol.MaxDimension)
	}
	o = RunTerminal(ctx, conn, hostID, IO{In: os.Stdin, Out: os.Stdout, Size: size, Resize: resize, Term: os.Getenv("TERM")})
	if o.Reason != protocol.EndRemoteExit && o.Ready {
		os.Stdout.WriteString(resetModes)
	}
	restore()
	return o, nil
}

// Explain is the message printed after the terminal is restored.
func Explain(o Outcome, alias string) string {
	var b strings.Builder
	switch {
	case o.Reason == protocol.EndRemoteExit:
		if o.Signal != "" {
			fmt.Fprintf(&b, "Connection to %s closed (remote signal %s).\n", alias, o.Signal)
		} else if o.ExitStatus == nil {
			fmt.Fprintf(&b, "Connection to %s closed (exit status unknown).\n", alias)
		} else if *o.ExitStatus != 0 {
			fmt.Fprintf(&b, "Connection to %s closed (exit status %d).\n", alias, *o.ExitStatus)
		}
		return b.String()
	case o.Reason == protocol.EndClientClose:
		fmt.Fprintf(&b, "Disconnected from %s.\n", alias)
	default:
		msg := o.Message
		if msg == "" {
			msg = protocol.Describe(o.Reason)
		}
		fmt.Fprintf(&b, "yunmen: %s: %s\n", alias, msg)
	}
	if o.Ready {
		fmt.Fprintf(&b, "Nothing was replayed. Reconnect with `yunmen connect %s`; run `tmux new -A -s main` on the host to keep work across disconnects.\n", alias)
	}
	return b.String()
}
