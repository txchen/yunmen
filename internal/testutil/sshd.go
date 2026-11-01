// Package testutil starts SSH targets for tests: the system OpenSSH sshd
// (realistic, key auth only when unprivileged) and an in-process Go server
// (password auth and controllable SFTP behavior).
package testutil

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Target is a running SSH server.
type Target struct {
	Address  string
	Port     int
	Username string
	HostKey  ssh.PublicKey
	// PrivateKey authenticates Username (OpenSSH PEM).
	PrivateKey []byte
	// Password authenticates Username on the Go server.
	Password string
	// Home is the account's working directory on the target.
	Home string
	// AuthorizedKeys is the authorized_keys file of the OpenSSH target.
	AuthorizedKeys string
}

func (t Target) Endpoint() string { return net.JoinHostPort(t.Address, strconv.Itoa(t.Port)) }

func newKey(t testing.TB) (ssh.Signer, []byte) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(block)
}

func freePort(t testing.TB) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

const sftpServer = "/usr/libexec/openssh/sftp-server"

// OpenSSH starts the system sshd as the current user. It skips the test when
// sshd is unavailable.
func OpenSSH(t testing.TB) Target {
	t.Helper()
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
			t.Skip("OpenSSH sshd not installed")
		}
		sshd = "/usr/sbin/sshd"
	}
	sftpPath := sftpServer
	if _, err := os.Stat(sftpPath); err != nil {
		sftpPath = "/usr/lib/openssh/sftp-server"
	}
	dir := t.TempDir()
	hostSigner, hostPEM := newKey(t)
	userSigner, userPEM := newKey(t)
	os.WriteFile(filepath.Join(dir, "hostkey"), hostPEM, 0o600)
	os.WriteFile(filepath.Join(dir, "authorized_keys"), ssh.MarshalAuthorizedKey(userSigner.PublicKey()), 0o600)
	port := freePort(t)
	home := filepath.Join(dir, "home")
	os.Mkdir(home, 0o700)
	cfg := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s/hostkey
AuthorizedKeysFile %s/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
StrictModes no
PidFile %s/sshd.pid
LogLevel ERROR
Subsystem sftp %s
ForceCommand %s/session.sh
`, port, dir, dir, dir, sftpPath, dir)
	os.WriteFile(filepath.Join(dir, "sshd_config"), []byte(cfg), 0o600)
	// Tests need a predictable shell, not the developer's login shell.
	script := fmt.Sprintf(`#!/bin/sh
case "$SSH_ORIGINAL_COMMAND" in
  sftp|*sftp-server) exec %s ;;
  "") cd %s; export INPUTRC=/dev/null; exec bash --norc --noprofile -i ;;
  *) exec /bin/sh -c "$SSH_ORIGINAL_COMMAND" ;;
esac
`, sftpPath, home)
	os.WriteFile(filepath.Join(dir, "session.sh"), []byte(script), 0o700)
	cmd := exec.Command(sshd, "-f", filepath.Join(dir, "sshd_config"), "-D", "-e")
	var logs bytes.Buffer
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sshd: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	waitListening(t, port, &logs)
	u, _ := user.Current()
	return Target{Address: "127.0.0.1", Port: port, Username: u.Username, HostKey: hostSigner.PublicKey(), PrivateKey: userPEM, Home: home,
		AuthorizedKeys: filepath.Join(dir, "authorized_keys")}
}

func waitListening(t testing.TB, port int, logs *bytes.Buffer) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("ssh server did not start: %s", logs.String())
}

// GoServerOptions configures the in-process server.
type GoServerOptions struct {
	NoSFTP bool
	// HostSigner replaces the generated host key (to simulate a key change, reuse the port with a new key).
	HostSigner ssh.Signer
	Port       int
}

// GoServer runs an in-process SSH server that accepts Password and the
// generated private key. Shell sessions run /bin/sh in a real PTY.
func GoServer(t testing.TB, o GoServerOptions) Target {
	t.Helper()
	hostSigner := o.HostSigner
	if hostSigner == nil {
		hostSigner, _ = newKey(t)
	}
	userSigner, userPEM := newKey(t)
	password := "target-password-" + strconv.Itoa(int(time.Now().UnixNano()%1e6))
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if string(p) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(k.Marshal(), userSigner.PublicKey().Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	cfg.AddHostKey(hostSigner)
	addr := "127.0.0.1:0"
	if o.Port != 0 {
		addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(o.Port))
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	home := t.TempDir()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go serveConn(c, cfg, home, o)
		}
	}()
	u, _ := user.Current()
	return Target{Address: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, Username: u.Username, HostKey: hostSigner.PublicKey(),
		PrivateKey: userPEM, Password: password, Home: home}
}

// NewHostSigner returns a fresh host key, for host-key-change tests.
func NewHostSigner(t testing.TB) ssh.Signer { s, _ := newKey(t); return s }

func serveConn(c net.Conn, cfg *ssh.ServerConfig, home string, o GoServerOptions) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go serveSession(ch, creqs, home, o)
	}
}

type ptyReq struct {
	Term          string
	Cols, Rows    uint32
	Width, Height uint32
	Modes         string
}

type winReq struct{ Cols, Rows, Width, Height uint32 }

func serveSession(ch ssh.Channel, reqs <-chan *ssh.Request, home string, o GoServerOptions) {
	defer ch.Close()
	var ptmx *os.File
	var size pty.Winsize
	termName := "xterm"
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			var p ptyReq
			ssh.Unmarshal(req.Payload, &p)
			size = pty.Winsize{Cols: uint16(p.Cols), Rows: uint16(p.Rows)}
			termName = p.Term
			req.Reply(true, nil)
		case "window-change":
			var w winReq
			ssh.Unmarshal(req.Payload, &w)
			size = pty.Winsize{Cols: uint16(w.Cols), Rows: uint16(w.Rows)}
			if ptmx != nil {
				pty.Setsize(ptmx, &size)
			}
		case "shell":
			cmd := exec.Command("/bin/sh")
			cmd.Dir = home
			cmd.Env = []string{"TERM=" + termName, "HOME=" + home, "PATH=/usr/bin:/bin", "PS1=$ "}
			f, err := pty.StartWithSize(cmd, &size)
			if err != nil {
				req.Reply(false, nil)
				return
			}
			ptmx = f
			req.Reply(true, nil)
			go func() {
				io.Copy(ch, f)
			}()
			go func() { io.Copy(f, ch) }()
			go func() {
				status := 0
				if err := cmd.Wait(); err != nil {
					if ee, ok := err.(*exec.ExitError); ok {
						status = ee.ExitCode()
					}
				}
				time.Sleep(50 * time.Millisecond)
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{uint32(status)}))
				ch.Close()
				f.Close()
			}()
		case "subsystem":
			if o.NoSFTP || len(req.Payload) < 4 || string(req.Payload[4:]) != "sftp" {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			srv, err := sftp.NewServer(ch, sftp.WithServerWorkingDirectory(home))
			if err != nil {
				return
			}
			srv.Serve()
			return
		default:
			req.Reply(false, nil)
		}
	}
}
