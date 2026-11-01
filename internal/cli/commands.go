package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/txchen/yunmen/internal/version"
	"golang.org/x/term"
)

const Usage = `usage:
  yunmen login <gateway-url> [--label <device name>]
  yunmen hosts
  yunmen connect [alias]
  yunmen logout
  yunmen version

While connected, type Enter ~ . to disconnect locally. Ctrl-C goes to the remote program.
`

// Main runs the CLI and returns the process exit code.
func Main(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, Usage)
		return 2
	}
	ctx := context.Background()
	var err error
	code := 0
	switch args[0] {
	case "login":
		err = login(ctx, args[1:])
	case "hosts":
		err = listHosts(ctx)
	case "connect":
		code, err = connect(ctx, args[1:])
	case "logout":
		err = logout(ctx)
	case "version", "--version":
		fmt.Println(version.Version)
	case "help", "-h", "--help":
		fmt.Print(Usage)
	default:
		fmt.Fprint(os.Stderr, Usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "yunmen:", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

func loggedIn() (Config, *Client, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return cfg, nil, err
	}
	s, err := LoadSecrets(cfg)
	if err != nil {
		return cfg, nil, err
	}
	gw, err := ParseGateway(cfg.Gateway)
	if err != nil {
		return cfg, nil, err
	}
	return cfg, NewClient(gw, s), nil
}

func prompt(t *console, r *bufio.Reader, label string) (string, error) {
	fmt.Fprint(t, label)
	line, err := r.ReadString('\n')
	return strings.TrimSpace(line), err
}

func login(ctx context.Context, args []string) error {
	var gatewayArg, label string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--label" && i+1 < len(args):
			label = args[i+1]
			i++
		case gatewayArg == "" && !strings.HasPrefix(args[i], "-"):
			gatewayArg = args[i]
		default:
			return errors.New("usage: yunmen login <gateway-url> [--label <device name>]")
		}
	}
	if gatewayArg == "" {
		return errors.New("usage: yunmen login <gateway-url> [--label <device name>]")
	}
	gw, err := ParseGateway(gatewayArg)
	if err != nil {
		return err
	}
	t, err := openConsole()
	if err != nil {
		return errors.New("login needs an interactive terminal for the hidden secret prompt")
	}
	defer t.Close()
	r := bufio.NewReader(t.in)

	if old, err := LoadConfig(); err == nil {
		if _, c, err := loggedIn(); err == nil {
			if c.Logout(ctx) == nil {
				fmt.Fprintln(t, "Revoked the previous device token for", old.Gateway)
			} else {
				fmt.Fprintln(t, "Note: could not revoke the previous device token; revoke it in Web > Devices.")
			}
		}
		DeleteLocal(old)
	}

	if label == "" {
		host, _ := os.Hostname()
		label = "yunmen CLI on " + host
	}
	// Only a gateway behind Cloudflare Access needs a service token; find
	// out by trying without one first.
	c := NewClient(gw, Secrets{})
	start, err := startPairing(ctx, c, label, func() (Secrets, error) {
		fmt.Fprintln(t, "This gateway is behind Cloudflare Access. Enter this device's Access service token.")
		return promptServiceToken(t, r)
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(t, "\nApprove this device in a browser (any device, signed in as the owner):\n\n  %s?code=%s\n\n  Device:  %s\n  Code:    %s\n\nWaiting for approval (expires %s)...\n",
		start.ApproveURL, start.UserCode, label, start.UserCode, start.ExpiresAt.Local().Format("15:04:05"))
	interval := time.Duration(max(start.Interval, 1)) * time.Second
	for {
		if time.Now().After(start.ExpiresAt) {
			return errors.New("approval request expired; run `yunmen login` again")
		}
		time.Sleep(interval)
		p, err := c.PairPoll(ctx, start.PollToken)
		if err != nil {
			return err
		}
		switch p.Status {
		case "pending":
		case "slow_down":
			interval += time.Second
		case "denied":
			return errors.New("approval denied in the browser")
		case "expired":
			return errors.New("approval request expired; run `yunmen login` again")
		case "approved":
			s := c.Secrets
			s.DeviceToken = p.DeviceToken
			where, err := SaveSecrets(gw.String(), s)
			if err != nil {
				return fmt.Errorf("approved, but could not store credentials: %w (revoke device %s in Web)", err, p.DeviceID)
			}
			cfg := Config{Gateway: gw.String(), DeviceID: p.DeviceID, Label: p.Label, ExpiresAt: p.ExpiresAt, SecretStore: where}
			if err := SaveConfig(cfg); err != nil {
				return err
			}
			fmt.Fprintf(t, "Approved. Device token valid until %s.\nCredentials stored in %s.\n", p.ExpiresAt, SecretsLocation(cfg))
			if where == "file" {
				fmt.Fprintln(t, "No OS credential store was available, so a private file is used instead.")
			}
			return nil
		default:
			return fmt.Errorf("unexpected approval status %q", p.Status)
		}
	}
}

// startPairing retries an Access-protected gateway after collecting its credentials.
func startPairing(ctx context.Context, c *Client, label string, prompt func() (Secrets, error)) (PairStart, error) {
	start, err := c.PairStart(ctx, label)
	if !NeedsAccessToken(err) {
		return start, err
	}
	secrets, err := prompt()
	if err != nil {
		return PairStart{}, err
	}
	c.Secrets = secrets
	return c.PairStart(ctx, label)
}

func promptServiceToken(t *console, r *bufio.Reader) (Secrets, error) {
	id, err := prompt(t, r, "Access Client ID: ")
	if err != nil {
		return Secrets{}, err
	}
	fmt.Fprint(t, "Access Client Secret (hidden): ")
	b, err := term.ReadPassword(int(t.in.Fd()))
	fmt.Fprintln(t)
	if err != nil {
		return Secrets{}, err
	}
	secret := strings.TrimSpace(string(b))
	if id == "" || secret == "" {
		return Secrets{}, errors.New("both the Access Client ID and Client Secret are required for this gateway")
	}
	return Secrets{AccessClientID: id, AccessClientSecret: secret}, nil
}

func listHosts(ctx context.Context) error {
	_, c, err := loggedIn()
	if err != nil {
		return err
	}
	hosts, err := c.Hosts(ctx)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		fmt.Println("No hosts. Add one in the web UI.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ALIAS\tNAME\tTARGET")
	for _, h := range hosts {
		fmt.Fprintf(w, "%s\t%s\t%s@%s\n", h.Alias, h.Name, h.Username, h.Endpoint)
	}
	return w.Flush()
}

// Filter returns hosts whose alias, name or endpoint contains q (case-insensitive).
func Filter(hosts []Host, q string) []Host {
	q = strings.ToLower(strings.TrimSpace(q))
	var out []Host
	for _, h := range hosts {
		if q == "" || strings.Contains(strings.ToLower(h.Alias+" "+h.Name+" "+h.Username+"@"+h.Endpoint), q) {
			out = append(out, h)
		}
	}
	return out
}

// selectHost is a line-based searchable selector: type to filter, a number
// to pick, Enter to take the only match, q to quit.
func selectHost(in io.Reader, out io.Writer, hosts []Host) (Host, error) {
	r := bufio.NewReader(in)
	matches := hosts
	for {
		for i, h := range matches {
			if i == 20 {
				fmt.Fprintf(out, "  ... %d more; type to filter\n", len(matches)-20)
				break
			}
			fmt.Fprintf(out, "  %2d) %-16s %s (%s@%s)\n", i+1, h.Alias, h.Name, h.Username, h.Endpoint)
		}
		fmt.Fprint(out, "Select host (number, or text to filter, q to quit): ")
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return Host{}, errors.New("no host selected")
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "q":
			return Host{}, errors.New("no host selected")
		case line == "" && len(matches) == 1:
			return matches[0], nil
		case line == "":
			continue
		}
		if n, err := strconv.Atoi(line); err == nil && n >= 1 && n <= len(matches) {
			return matches[n-1], nil
		}
		for _, h := range hosts {
			if h.Alias == line {
				return h, nil
			}
		}
		next := Filter(hosts, line)
		if len(next) == 0 {
			fmt.Fprintf(out, "No host matches %q.\n", line)
			continue
		}
		matches = next
	}
}

func connect(ctx context.Context, args []string) (int, error) {
	if len(args) > 1 {
		return 2, errors.New("usage: yunmen connect [alias]")
	}
	_, c, err := loggedIn()
	if err != nil {
		return 1, err
	}
	hosts, err := c.Hosts(ctx)
	if err != nil {
		return 1, err
	}
	var host Host
	if len(args) == 1 {
		found := false
		for _, h := range hosts {
			if h.Alias == args[0] {
				host, found = h, true
			}
		}
		if !found {
			return 1, fmt.Errorf("no host with alias %q; see `yunmen hosts`", args[0])
		}
	} else {
		if len(hosts) == 0 {
			return 1, errors.New("no hosts configured; add one in the web UI")
		}
		host, err = selectHost(os.Stdin, os.Stderr, hosts)
		if err != nil {
			return 1, err
		}
	}
	conn, err := c.DialTerminal(ctx)
	if err != nil {
		return 255, err
	}
	o, err := Interactive(ctx, conn, host.ID)
	if err != nil {
		return 255, err
	}
	fmt.Fprint(os.Stderr, Explain(o, host.Alias))
	return o.ExitCode(), nil
}

func logout(ctx context.Context) error {
	cfg, c, err := loggedIn()
	if err != nil {
		if cfg.Gateway != "" {
			DeleteLocal(cfg)
			fmt.Println("Local credentials removed. Remote revocation NOT performed: revoke this device in Web > Devices.")
		}
		return err
	}
	revokeErr := c.Logout(ctx)
	if err := DeleteLocal(cfg); err != nil {
		return fmt.Errorf("could not remove local credentials: %w", err)
	}
	fmt.Println("Local credentials removed (device token and Access service token).")
	if revokeErr != nil {
		fmt.Printf("Remote revocation has NOT completed: %v\nRevoke device %q (%s) in Web > Devices.\n", revokeErr, cfg.Label, cfg.DeviceID)
	} else {
		fmt.Println("Device token revoked on the gateway.")
	}
	fmt.Println("The Cloudflare Access service token itself is still valid; revoke it in Cloudflare Zero Trust if it is no longer needed.")
	if revokeErr != nil {
		return errors.New("remote revocation pending")
	}
	return nil
}
