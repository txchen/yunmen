// Command yunmen-server runs the Yunmen gateway and its local administration
// commands.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mdp/qrterminal/v3"
	"github.com/txchen/yunmen/internal/auth"
	"github.com/txchen/yunmen/internal/secrets"
	"github.com/txchen/yunmen/internal/server"
	"github.com/txchen/yunmen/internal/store"
	"github.com/txchen/yunmen/internal/version"
	"github.com/txchen/yunmen/web"
	"golang.org/x/term"
)

const usage = `usage: yunmen-server <command>

commands:
  serve            run the gateway (default)
  init             create the owner account and enroll TOTP (run locally, once)
  reset-password   set a new owner password; revokes all sessions and devices
  reset-totp       enroll a new TOTP secret; revokes all sessions and devices
  revoke-all       revoke every browser session and CLI device (after a restore)
  recovery-codes   replace the owner's recovery codes and print the new ones
  genkey           print a new random master key
  version          print the version

environment: see docs/operations.md
`

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "init":
		err = initOwner()
	case "reset-password":
		err = resetPassword()
	case "reset-totp":
		err = resetTOTP()
	case "revoke-all":
		err = revokeAll()
	case "recovery-codes":
		err = recoveryCodes()
	case "genkey":
		fmt.Println(secrets.Generate())
	case "version":
		fmt.Println(version.Version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "yunmen-server:", err)
		os.Exit(1)
	}
}

func dataDir() string {
	if d := os.Getenv("YUNMEN_DATA_DIR"); d != "" {
		return d
	}
	return "./data"
}

func openStore(ctx context.Context, dir string) (*store.Store, error) {
	key, err := secrets.Load(os.Getenv)
	if err != nil {
		return nil, err
	}
	return store.Open(ctx, server.Config{DataDir: dir}.DBPath(), key)
}

func serve() error {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := server.LoadConfig(os.Getenv)
	if err != nil {
		return fmt.Errorf("configuration:\n%w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st, err := openStore(ctx, cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	if ok, _ := st.HasOwner(ctx); !ok {
		log.Warn("owner not initialized; run `yunmen-server init` locally before signing in")
	}
	var verifier *auth.AccessVerifier
	if cfg.Mode == server.ModeAccess {
		verifier = auth.NewAccessVerifier(cfg.Access, &http.Client{Timeout: 10 * time.Second})
	} else {
		log.Warn("standalone mode: Cloudflare Access is not enforced; Yunmen password and TOTP still are")
	}
	srv := server.New(server.Options{Config: cfg, Store: st, Access: verifier, Log: log, Web: web.FS()})
	go srv.Files().CleanupPending(ctx)
	go srv.RunSweeper(ctx, 15*time.Second)
	hs := &http.Server{Addr: cfg.Listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("yunmen listening", "addr", cfg.Listen, "mode", cfg.Mode, "origin", cfg.OriginString(), "version", version.Version)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	srv.Shutdown(context.Background())
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := hs.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func tty() (*os.File, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("this command must run in an interactive terminal")
	}
	return f, nil
}

func readSecret(t *os.File, prompt string) (string, error) {
	fmt.Fprint(t, prompt)
	b, err := term.ReadPassword(int(t.Fd()))
	fmt.Fprintln(t)
	return string(b), err
}

func newPassword(t *os.File) (string, error) {
	for {
		p1, err := readSecret(t, fmt.Sprintf("New owner password (min %d characters): ", auth.MinPassword))
		if err != nil {
			return "", err
		}
		if len(p1) < auth.MinPassword {
			fmt.Fprintln(t, "Too short.")
			continue
		}
		p2, err := readSecret(t, "Repeat password: ")
		if err != nil {
			return "", err
		}
		if p1 != p2 {
			fmt.Fprintln(t, "Passwords do not match.")
			continue
		}
		return auth.HashPassword(p1)
	}
}

// enrollTOTP shows a new secret and requires one valid code before returning it.
func enrollTOTP(t *os.File) ([]byte, error) {
	secret := auth.NewTOTPSecret()
	uri := auth.TOTPURI(secret, "owner")
	fmt.Fprintln(t, "\nScan this QR code with your authenticator app:")
	qrterminal.GenerateHalfBlock(uri, qrterminal.L, t)
	fmt.Fprintf(t, "\nOr enter this secret manually: %s\n(TOTP, SHA-1, 6 digits, 30 seconds)\n\n", auth.TOTPBase32(secret))
	in := bufio.NewReader(t)
	for attempt := 0; attempt < 5; attempt++ {
		fmt.Fprint(t, "Enter the current 6-digit code to confirm: ")
		line, err := in.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if _, ok := auth.MatchTOTP(secret, strings.TrimSpace(line), time.Now()); ok {
			return secret, nil
		}
		fmt.Fprintln(t, "Code does not match. Check the device clock and try again.")
	}
	return nil, errors.New("TOTP enrollment not confirmed; nothing was saved")
}

func initOwner() error {
	ctx := context.Background()
	st, err := openStore(ctx, dataDir())
	if err != nil {
		return err
	}
	defer st.Close()
	if ok, err := st.HasOwner(ctx); err != nil || ok {
		if ok {
			return errors.New("owner already initialized; use reset-password or reset-totp for recovery")
		}
		return err
	}
	t, err := tty()
	if err != nil {
		return err
	}
	defer t.Close()
	hash, err := newPassword(t)
	if err != nil {
		return err
	}
	secret, err := enrollTOTP(t)
	if err != nil {
		return err
	}
	codes, err := st.CreateOwner(ctx, hash, secret)
	if err != nil {
		return err
	}
	printRecoveryCodes(t, codes)
	fmt.Fprintln(t, "Owner initialized. Back up the database and the master key separately (docs/operations.md).")
	return nil
}

func resetPassword() error {
	ctx := context.Background()
	st, err := openStore(ctx, dataDir())
	if err != nil {
		return err
	}
	defer st.Close()
	t, err := tty()
	if err != nil {
		return err
	}
	defer t.Close()
	if _, err := st.Owner(ctx); err != nil {
		return err
	}
	hash, err := newPassword(t)
	if err != nil {
		return err
	}
	if err := st.ResetOwnerSecrets(ctx, hash, nil); err != nil {
		return err
	}
	fmt.Fprintln(t, "Password replaced. All browser sessions and CLI devices are revoked; a running server closes their open terminals within about 15 seconds.")
	return nil
}

func resetTOTP() error {
	ctx := context.Background()
	st, err := openStore(ctx, dataDir())
	if err != nil {
		return err
	}
	defer st.Close()
	t, err := tty()
	if err != nil {
		return err
	}
	defer t.Close()
	if _, err := st.Owner(ctx); err != nil {
		return err
	}
	secret, err := enrollTOTP(t)
	if err != nil {
		return err
	}
	if err := st.ResetOwnerSecrets(ctx, "", secret); err != nil {
		return err
	}
	fmt.Fprintln(t, "TOTP re-enrolled. All browser sessions and CLI devices are revoked; a running server closes their open terminals within about 15 seconds.")
	return nil
}

func revokeAll() error {
	ctx := context.Background()
	st, err := openStore(ctx, dataDir())
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.ResetOwnerSecrets(ctx, "", nil); err != nil {
		return err
	}
	fmt.Println("All browser sessions and CLI devices revoked. A running server closes their open terminals within about 15 seconds.")
	return nil
}

func printRecoveryCodes(w *os.File, codes []string) {
	fmt.Fprintln(w, "\nRecovery codes. Each works once to replace a lost authenticator.")
	fmt.Fprintln(w, "Store them somewhere safe now; they are not shown again:")
	for i := 0; i < len(codes); i += 2 {
		fmt.Fprintf(w, "  %s   %s\n", codes[i], codes[i+1])
	}
	fmt.Fprintln(w)
}

func recoveryCodes() error {
	ctx := context.Background()
	st, err := openStore(ctx, dataDir())
	if err != nil {
		return err
	}
	defer st.Close()
	if _, err := st.Owner(ctx); err != nil {
		return err
	}
	codes, err := st.ReplaceRecoveryCodes(ctx)
	if err != nil {
		return err
	}
	printRecoveryCodes(os.Stdout, codes)
	fmt.Println("Previous recovery codes no longer work.")
	return nil
}
