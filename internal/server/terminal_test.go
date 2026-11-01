package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/txchen/yunmen/internal/live"
	"github.com/txchen/yunmen/internal/protocol"
	"github.com/txchen/yunmen/internal/store"
	"github.com/txchen/yunmen/internal/testutil"
)

func sshdHost(t *testing.T, mode Mode) (*harness, *client, string, testutil.Target) {
	tgt := testutil.OpenSSH(t)
	h := newHarness(t, mode)
	owner := h.browser()
	owner.login()
	id := h.addHost(owner, "box", tgt, keyAuth(tgt))
	return h, owner, id, tgt
}

func TestTerminalUnicodeResizeCtrlCAndExit(t *testing.T) {
	_, owner, id, _ := sshdHost(t, ModeStandalone)
	tm := owner.openTerm(id)
	if tm.end != nil {
		t.Fatalf("open failed: %+v", tm.end)
	}
	tm.send([]byte("export LANG=C.UTF-8 PS1='$ '; printf 'u:%s:\\n' '中文 emoji 😀 e\xcc\x81 ┌─┐'\r"))
	tm.expect("u:中文 emoji 😀 e\xcc\x81 ┌─┐:")

	tm.send([]byte("stty size\r"))
	tm.expect("24 80")
	tm.control(protocol.Control{Type: protocol.TypeResize, Cols: 132, Rows: 43})
	tm.send([]byte("stty size\r"))
	tm.expect("43 132")

	tm.send([]byte("sleep 30; echo slept\r"))
	time.Sleep(300 * time.Millisecond)
	tm.send([]byte{0x03})
	// INTR flushes the tty input queue, so typed-ahead input would be lost.
	time.Sleep(300 * time.Millisecond)
	tm.send([]byte("echo after-$((40+2))\r"))
	tm.expect("after-42")
	if strings.Contains(tm.out.String(), "\nslept") {
		t.Fatal("Ctrl-C did not interrupt the remote program")
	}

	tm.send([]byte("exit 7\r"))
	end := tm.waitEnd(10 * time.Second)
	if end.Reason != protocol.EndRemoteExit || end.ExitStatus == nil || *end.ExitStatus != 7 {
		t.Fatalf("end = %+v", end)
	}
}

// Generated-input property: arbitrary byte sequences, every byte value
// included, pass gateway -> pty (raw) -> cat -> gateway unchanged, at sizes
// that exceed the output window so flow control is exercised.
func TestTerminalPreservesArbitraryBytes(t *testing.T) {
	_, owner, id, _ := sshdHost(t, ModeStandalone)
	tm := owner.openTerm(id)
	tm.send([]byte("stty raw -echo -iexten; printf 'RE%sDY' A; cat; stty sane\r"))
	tm.expect("READY")
	rng := rand.New(rand.NewPCG(1, 2))
	for _, size := range []int{1, 255, 4096, 70_000, 600_000} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(rng.IntN(256))
		}
		if size >= 255 {
			for i := 0; i < 256; i++ {
				payload[i%size] = byte(i)
			}
		}
		start := tm.out.Len()
		go tm.sendAsync(payload)
		ok := tm.readUntil(60*time.Second, func(b []byte) bool { return len(b)-start >= size })
		got := tm.out.Bytes()[start:]
		if !ok || !bytes.Equal(got[:size], payload) {
			t.Fatalf("size %d: bytes differ (got %d bytes, first diff at %d) got=%q want=%q", size, len(got), firstDiff(got, payload), got[:min(len(got), 40)], payload[:min(size, 40)])
		}
	}
}

func (tm *term) sendAsync(b []byte) {
	for len(b) > 0 {
		n := min(len(b), protocol.MaxPayload)
		if tm.conn.Write(context.Background(), websocket.MessageBinary, b[:n]) != nil {
			return
		}
		b = b[n:]
	}
}

func firstDiff(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

func TestVimAndTmuxRun(t *testing.T) {
	_, owner, id, tgt := sshdHost(t, ModeStandalone)
	tm := owner.openTerm(id)
	file := tgt.Home + "/vim-test.txt"
	tm.send([]byte("export LANG=C.UTF-8; vim -u NONE -N " + file + "\r"))
	tm.expect("\x1b[?1049h")
	// Pause after ESC so vim does not read ESC+':' as one key sequence.
	tm.send([]byte("iline 中文\x1b"))
	time.Sleep(200 * time.Millisecond)
	tm.send([]byte(":wq\r"))
	tm.expect("\x1b[?1049l")
	tm.send([]byte("cat " + file + "; echo VIMDONE\r"))
	tm.expect("line 中文")
	tm.expect("VIMDONE")

	sock := tgt.Home + "/tmux.sock"
	tm.send([]byte("tmux -S " + sock + " -f /dev/null new -s main bash --norc --noprofile\r"))
	tm.expect("[main]")
	time.Sleep(300 * time.Millisecond)
	tm.send([]byte("echo in-$((6*7))\r"))
	tm.expect("in-42")
	tm.conn.Close(websocket.StatusNormalClosure, "")

	// Reconnect: a new shell, nothing replayed, and the tmux session survives.
	tm2 := owner.openTerm(id)
	tm2.send([]byte("tmux -S " + sock + " -f /dev/null attach -t main\r"))
	tm2.expect("in-42")
	tm2.send([]byte{0x02})
	time.Sleep(200 * time.Millisecond)
	tm2.send([]byte("d"))
	tm2.expect("detached")
	tm2.send([]byte("tmux -S " + sock + " kill-server; exit\r"))
	tm2.waitEnd(10 * time.Second)
}

func TestDeviceRevocationClosesOnlyThatDevice(t *testing.T) {
	h, owner, id, _ := sshdHost(t, ModeAccess)
	cliA, devA := h.pair(owner, serviceID, "laptop")
	cliB, _ := h.pair(owner, "svc-other.access", "desktop")
	a1, a2, b := cliA.openTerm(id), cliA.openTerm(id), cliB.openTerm(id)
	web := owner.openTerm(id)

	if n := h.srv.reg.Count(live.DeviceCredential(devA)); n != 2 {
		t.Fatalf("device A terminals = %d", n)
	}
	st, res := owner.do("POST", "/api/v1/devices/"+devA+"/revoke", map[string]string{})
	if st != 200 || res["closedTerminals"].(float64) != 2 {
		t.Fatalf("revoke: %d %v", st, res)
	}
	for _, tm := range []*term{a1, a2} {
		if end := tm.waitEnd(5 * time.Second); end.Reason != protocol.EndRevoked {
			t.Fatalf("revoked terminal ended with %+v", end)
		}
	}
	for _, tm := range []*term{b, web} {
		tm.send([]byte("echo still-$((1+1))\r"))
		tm.expect("still-2")
	}
	if st, _ := cliA.do("GET", "/api/v1/cli/hosts", nil); st != 401 {
		t.Fatalf("revoked device still lists hosts: %d", st)
	}
	if _, st := cliA.dialTerm(); st != 401 {
		t.Fatalf("revoked device opened upgrade: %d", st)
	}
}

// Revocation racing with opening: every terminal either fails to open or is
// ended by the revocation. None stays running.
func TestRevocationRacingWithOpen(t *testing.T) {
	h, owner, id, _ := sshdHost(t, ModeStandalone)
	cli, dev := h.pair(owner, StandalonePrincipal, "laptop")
	var wg sync.WaitGroup
	terms := make([]*term, 8)
	for i := range terms {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, st := cli.dialTerm()
			if st != 0 {
				return
			}
			tm := &term{t: t, conn: conn}
			tm.control(protocol.Control{Type: protocol.TypeOpen, HostID: id, Cols: 80, Rows: 24})
			terms[i] = tm
		}()
		if i == 4 {
			time.Sleep(time.Duration(rand.IntN(20)) * time.Millisecond)
			owner.do("POST", "/api/v1/devices/"+dev+"/revoke", map[string]string{})
		}
	}
	wg.Wait()
	for _, tm := range terms {
		if tm == nil {
			continue
		}
		end := tm.waitEnd(20 * time.Second)
		if end.Reason != protocol.EndRevoked {
			t.Fatalf("terminal ended with %+v, want revoked", end)
		}
	}
	waitCount(t, h, live.DeviceCredential(dev))
}

func TestActiveTerminalEndsAtCredentialExpiry(t *testing.T) {
	h, owner, id, _ := sshdHost(t, ModeStandalone)
	// Issue the device as if approved 30 days minus 2 seconds ago.
	h.store.SetClock(func() time.Time { return time.Now().Add(-30*24*time.Hour + 2*time.Second) })
	cli, _ := h.pair(owner, StandalonePrincipal, "laptop")
	h.store.SetClock(time.Now)
	tm := cli.openTerm(id)
	if tm.end != nil {
		t.Fatalf("open: %+v", tm.end)
	}
	if end := tm.waitEnd(10 * time.Second); end.Reason != protocol.EndExpired {
		t.Fatalf("end = %+v", end)
	}
}

func TestHostDeletionClosesTerminals(t *testing.T) {
	_, owner, id, _ := sshdHost(t, ModeStandalone)
	tm := owner.openTerm(id)
	if st, _ := owner.do("DELETE", "/api/v1/hosts/"+id, nil); st != 204 {
		t.Fatalf("delete: %d", st)
	}
	if end := tm.waitEnd(5 * time.Second); end.Reason != protocol.EndHostRemoved {
		t.Fatalf("end = %+v", end)
	}
}

func TestChangedHostKeyRefusedBeforeAuth(t *testing.T) {
	first := testutil.GoServer(t, testutil.GoServerOptions{})
	h := newHarness(t, ModeStandalone)
	owner := h.browser()
	owner.login()
	id := h.addHost(owner, "pw", first, passwordAuth(first))
	tm := owner.openTerm(id)
	tm.send([]byte("echo pw-$((2+3))\r"))
	tm.expect("pw-5")

	// Same endpoint, new host key: simulates a replaced or impersonated target.
	host, _ := h.store.GetHost(context.Background(), id)
	impostor := testutil.GoServer(t, testutil.GoServerOptions{HostSigner: testutil.NewHostSigner(t)})
	h.store.UpdateHost(context.Background(), id, host.Revision, updateEndpoint(host, impostor))
	tm2 := owner.openTerm(id)
	if tm2.end == nil || tm2.end.Reason != protocol.EndHostKeyChanged {
		t.Fatalf("changed host key not refused: %+v", tm2.end)
	}
}

func TestWrongTargetPasswordReported(t *testing.T) {
	tgt := testutil.GoServer(t, testutil.GoServerOptions{})
	h := newHarness(t, ModeStandalone)
	owner := h.browser()
	owner.login()
	_, probe := owner.do("POST", "/api/v1/hosts/probe", map[string]any{"address": tgt.Address, "port": tgt.Port})
	st, res := owner.do("POST", "/api/v1/hosts", map[string]any{"alias": "pw", "address": tgt.Address, "port": tgt.Port, "username": tgt.Username,
		"auth": map[string]string{"kind": "password", "password": "wrong"}, "observationId": probe["observationId"]})
	if st != 422 || res["reason"] != string(protocol.EndAuthFailed) {
		t.Fatalf("wrong password: %d %v", st, res)
	}
	if st, _ := owner.do("POST", "/api/v1/hosts", map[string]any{"alias": "pw", "address": tgt.Address, "port": tgt.Port, "username": tgt.Username,
		"auth": passwordAuth(tgt)}); st != 400 {
		t.Fatalf("host saved without verified host key: %d", st)
	}
}

func TestTerminalRejectsProtocolViolations(t *testing.T) {
	h, owner, id, _ := sshdHost(t, ModeStandalone)
	conn, _ := owner.dialTerm()
	conn.Write(context.Background(), websocket.MessageBinary, []byte("ls\r"))
	tm := &term{t: t, conn: conn}
	if end := tm.waitEnd(5 * time.Second); end.Reason != protocol.EndProtocolError {
		t.Fatalf("binary before open: %+v", end)
	}
	tm = owner.openTerm(id)
	tm.control(protocol.Control{Type: protocol.TypeAck, Bytes: 1 << 40})
	if end := tm.waitEnd(5 * time.Second); end.Reason != protocol.EndProtocolError {
		t.Fatalf("ack beyond sent: %+v", end)
	}
	waitCount(t, h, "")
}

func TestSlowConsumerEndsWithoutUnboundedBuffering(t *testing.T) {
	tgt := testutil.OpenSSH(t)
	h := newHarness(t, ModeStandalone)
	h.srv.termDeps.SlowConsumer = 2 * time.Second
	owner := h.browser()
	owner.login()
	id := h.addHost(owner, "box", tgt, keyAuth(tgt))
	tm := owner.openTerm(id)
	tm.send([]byte("yes yunmen-flood\r"))
	// Read without acking: the server must stop at the window and give up.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var unacked int
	for {
		typ, data, err := tm.conn.Read(ctx)
		if err != nil {
			t.Fatalf("no end before timeout; received %d unacked bytes", unacked)
		}
		if typ == websocket.MessageBinary {
			unacked += len(data)
			continue
		}
		if c, _ := protocol.ParseServer(data); c.Type == protocol.TypeEnd {
			if c.Reason != protocol.EndSlowConsumer {
				t.Fatalf("end = %+v", c)
			}
			break
		}
	}
	if unacked > protocol.OutputWindow+protocol.MaxPayload {
		t.Fatalf("server sent %d unacknowledged bytes, window is %d", unacked, protocol.OutputWindow)
	}
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// updateEndpoint points host at another server while keeping the old pin.
func updateEndpoint(h store.Host, to testutil.Target) store.HostUpdate {
	return store.HostUpdate{Spec: store.HostSpec{Alias: h.Alias, Name: h.Name, Address: to.Address, Port: to.Port, Username: h.Username}, HostKey: h.HostKey}
}

// waitCount fails unless no operation for cred stays registered.
func waitCount(t *testing.T, h *harness, cred live.Credential) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for h.srv.reg.Count(cred) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d operations still registered", h.srv.reg.Count(cred))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Input the remote never reads fills the SSH channel; the client honors the
// input window, and control messages such as close must still get through.
func TestControlsStayResponsiveWhenRemoteStopsReadingInput(t *testing.T) {
	_, owner, id, _ := sshdHost(t, ModeStandalone)
	tm := owner.openTerm(id)
	tm.send([]byte("stty -echo -icanon; sleep 60\r"))
	time.Sleep(500 * time.Millisecond)
	go func() {
		chunk := bytes.Repeat([]byte("x"), protocol.MaxPayload)
		var sent int64
		for sent < 8<<20 {
			for sent-tm.inputAcked.Load()+int64(len(chunk)) > protocol.InputWindow {
				time.Sleep(5 * time.Millisecond)
			}
			if tm.conn.Write(context.Background(), websocket.MessageBinary, chunk) != nil {
				return
			}
			sent += int64(len(chunk))
		}
	}()
	// One reader for the whole test: coder/websocket closes the connection
	// when a Read context expires, so no short read timeouts here.
	ended := make(chan protocol.Control, 1)
	go func() {
		for {
			typ, data, err := tm.conn.Read(context.Background())
			if err != nil {
				close(ended)
				return
			}
			if typ == websocket.MessageBinary {
				continue
			}
			c, _ := protocol.ParseServer(data)
			switch c.Type {
			case protocol.TypeAck:
				tm.inputAcked.Store(c.Bytes)
			case protocol.TypeEnd:
				ended <- c
				return
			}
		}
	}()
	var last int64 = -1
	for i := 0; i < 100; i++ {
		time.Sleep(300 * time.Millisecond)
		if cur := tm.inputAcked.Load(); cur == last && cur > 0 {
			break
		} else {
			last = cur
		}
	}
	if last >= 8<<20 {
		t.Fatal("remote consumed all input; the channel never filled")
	}
	start := time.Now()
	tm.control(protocol.Control{Type: protocol.TypeClose})
	select {
	case end := <-ended:
		if end.Reason != protocol.EndClientClose {
			t.Fatalf("end %+v", end)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("close not processed within 3s while input was blocked (acked %d)", last)
	}
	_ = start
}

// Local recovery runs in another process and only writes the database; the
// sweep must end terminals that are already open.
func TestSweepEndsTerminalsRevokedByAnotherProcess(t *testing.T) {
	h, owner, id, _ := sshdHost(t, ModeStandalone)
	cli, _ := h.pair(owner, StandalonePrincipal, "laptop")
	web, dev := owner.openTerm(id), cli.openTerm(id)
	h.srv.SweepRevoked(context.Background())
	if h.srv.reg.Count("") != 2 {
		t.Fatal("sweep ended active credentials")
	}
	if err := h.store.ResetOwnerSecrets(context.Background(), "", nil); err != nil {
		t.Fatal(err)
	}
	h.srv.SweepRevoked(context.Background())
	for _, tm := range []*term{web, dev} {
		if end := tm.waitEnd(5 * time.Second); end.Reason != protocol.EndRevoked {
			t.Fatalf("end %+v", end)
		}
	}
}

func TestPerCredentialTerminalCap(t *testing.T) {
	h, owner, id, _ := sshdHost(t, ModeStandalone)
	cli, dev := h.pair(owner, StandalonePrincipal, "laptop")
	for i := 0; i < live.MaxPerCredential; i++ {
		if _, err := h.srv.reg.Register(live.DeviceCredential(dev), id, live.KindTerminal, time.Now().Add(time.Hour), func(protocol.EndReason) {}); err != nil {
			t.Fatal(err)
		}
	}
	tm := cli.openTerm(id)
	if tm.end == nil || tm.end.Reason != protocol.EndOpenFailed || !strings.Contains(tm.end.Message, "too many") {
		t.Fatalf("over-cap open: %+v", tm.end)
	}
	if web := owner.openTerm(id); web.end != nil {
		t.Fatalf("cap leaked to another credential: %+v", web.end)
	}
}
