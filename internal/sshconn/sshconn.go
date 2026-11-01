// Package sshconn is the one place that turns a host snapshot into an
// authenticated SSH connection. It verifies the pinned host key before any
// credential is offered and never consults ambient SSH configuration.
package sshconn

import (
	"bytes"
	"context"
	"crypto/dsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/txchen/yunmen/internal/protocol"
	"github.com/txchen/yunmen/internal/store"
	"golang.org/x/crypto/ssh"
)

const handshakeTimeout = 15 * time.Second

// Error carries the end reason clients should see. Messages never contain
// credential material.
type Error struct {
	Reason protocol.EndReason
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

func ReasonOf(err error) protocol.EndReason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return protocol.EndOpenFailed
}

func dialTCP(ctx context.Context, endpoint string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{protocol.EndTargetUnreachable, "cannot reach " + endpoint + ": " + scrub(err)}
	}
	return conn, nil
}

func scrub(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}

// HostKeyAlgorithms restricts negotiation to the pinned key's type so a server
// with several host keys presents the one that was verified. RSA host keys
// must sign with SHA-2 (OpenSSH 7.2+); SHA-1 "ssh-rsa" signatures are refused.
func HostKeyAlgorithms(key ssh.PublicKey) []string {
	if key.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{key.Type()}
}

// Dial opens an authenticated client using exactly the host's configured
// credential. Cancelling ctx aborts the connection at any stage; once it
// returns, the caller owns the client and must Close it.
func Dial(ctx context.Context, h store.Host, cred store.Credential) (*ssh.Client, error) {
	pinned, err := ssh.ParsePublicKey(h.HostKey)
	if err != nil {
		return nil, &Error{protocol.EndHostKeyUnknown, "host has no valid pinned key"}
	}
	var auth ssh.AuthMethod
	switch cred.Kind {
	case store.AuthKey:
		signer, err := ssh.ParsePrivateKey(cred.PrivateKey)
		if err != nil {
			return nil, &Error{protocol.EndOpenFailed, "saved private key is unusable"}
		}
		auth = ssh.PublicKeys(signer)
	case store.AuthPassword:
		auth = ssh.Password(cred.Password)
	default:
		return nil, &Error{protocol.EndOpenFailed, "unknown authentication kind"}
	}
	var trust protocol.EndReason
	cfg := &ssh.ClientConfig{
		User:              h.Username,
		Auth:              []ssh.AuthMethod{auth},
		HostKeyAlgorithms: HostKeyAlgorithms(pinned),
		Timeout:           handshakeTimeout,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !bytes.Equal(key.Marshal(), pinned.Marshal()) {
				trust = protocol.EndHostKeyChanged
				return errors.New("host key mismatch")
			}
			return nil
		},
	}
	conn, err := dialTCP(ctx, h.Endpoint())
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, h.Endpoint(), cfg)
	if !stop() || ctx.Err() != nil {
		if err == nil {
			c.Close()
		}
		conn.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		conn.Close()
		switch {
		case trust != "":
			return nil, &Error{trust, fmt.Sprintf("host key for %s does not match the pinned key (%s); refusing to send credentials", h.Endpoint(), ssh.FingerprintSHA256(pinned))}
		case strings.Contains(err.Error(), "unable to authenticate"):
			return nil, &Error{protocol.EndAuthFailed, "target rejected the saved " + string(cred.Kind) + " credential for user " + h.Username}
		}
		return nil, &Error{protocol.EndTargetUnreachable, "ssh handshake with " + h.Endpoint() + " failed: " + scrub(err)}
	}
	conn.SetDeadline(time.Time{})
	client := ssh.NewClient(c, chans, reqs)
	// Close the client when ctx ends so every channel on it is torn down.
	context.AfterFunc(ctx, func() { client.Close() })
	return client, nil
}

var errProbeDone = errors.New("probe complete")

// Probe fetches the host's public key without attempting user authentication.
func Probe(ctx context.Context, endpoint string) (ssh.PublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	conn, err := dialTCP(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	var seen ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "yunmen-probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = key
			return errProbeDone
		},
		Timeout: handshakeTimeout,
	}
	_, _, _, err = ssh.NewClientConn(conn, endpoint, cfg)
	if seen != nil {
		return seen, nil
	}
	if ctx.Err() != nil {
		return nil, &Error{protocol.EndTargetUnreachable, "timed out probing " + endpoint}
	}
	return nil, &Error{protocol.EndTargetUnreachable, "ssh handshake with " + endpoint + " failed: " + scrub(err)}
}

// ImportPrivateKey parses an OpenSSH, PKCS#1, SEC1 or PKCS#8 private key
// (optionally passphrase protected) and returns it re-encoded as an
// unencrypted OpenSSH key plus its public fingerprint. The passphrase is not
// retained.
func ImportPrivateKey(pemBytes []byte, passphrase string) ([]byte, string, error) {
	var raw any
	var err error
	if passphrase == "" {
		raw, err = ssh.ParseRawPrivateKey(pemBytes)
	} else {
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
	}
	var missing *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &missing):
		return nil, "", errors.New("private key is encrypted: supply its passphrase")
	case errors.Is(err, x509.IncorrectPasswordError):
		return nil, "", errors.New("passphrase is incorrect")
	case err != nil:
		return nil, "", errors.New("unsupported or malformed private key; supported: OpenSSH, PKCS#1, SEC1, PKCS#8 encodings of Ed25519, ECDSA and RSA keys")
	}
	if _, ok := raw.(*dsa.PrivateKey); ok {
		return nil, "", errors.New("DSA keys are not supported")
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, "", errors.New("unsupported private key type")
	}
	block, err := ssh.MarshalPrivateKey(raw, "yunmen")
	if err != nil {
		return nil, "", errors.New("unsupported private key type")
	}
	if k, ok := raw.(*rsa.PrivateKey); ok && k.N.BitLen() < 2048 {
		return nil, "", errors.New("RSA keys shorter than 2048 bits are not supported")
	}
	return pem.EncodeToMemory(block), ssh.FingerprintSHA256(signer.PublicKey()), nil
}
