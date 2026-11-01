// Package protocol defines the terminal WebSocket contract shared by the
// server, the CLI and (mirrored in TypeScript) the web client.
//
// Binary WebSocket messages carry raw terminal bytes. Text messages carry
// exactly one JSON Control object. The two never mix.
package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"unicode"
)

const (
	Subprotocol = "yunmen.term.v1"
	Path        = "/api/v1/terminal"

	// MaxPayload bounds one binary frame in either direction.
	MaxPayload = 16 * 1024
	// MaxControl bounds one text control frame.
	MaxControl = 4 * 1024
	// OutputWindow is the unacknowledged output budget the server may have in flight.
	OutputWindow = 256 * 1024
	// InputWindow is the unacknowledged input budget a client may have in flight.
	InputWindow = 64 * 1024

	MinDimension = 1
	MaxDimension = 1000
)

type ControlType string

const (
	TypeOpen   ControlType = "open"   // client -> server, first message
	TypeReady  ControlType = "ready"  // server -> client, shell started
	TypeResize ControlType = "resize" // client -> server
	TypeAck    ControlType = "ack"    // both ways: cumulative bytes consumed
	TypeClose  ControlType = "close"  // client -> server, user asked to disconnect
	TypeEnd    ControlType = "end"    // server -> client, final message
)

// EndReason classifies why a terminal ended. Clients render it next to, never
// over, the terminal contents.
type EndReason string

const (
	EndRemoteExit        EndReason = "remote_exit"
	EndClientClose       EndReason = "client_close"
	EndAuthFailed        EndReason = "target_auth_failed"
	EndHostKeyUnknown    EndReason = "host_key_unknown"
	EndHostKeyChanged    EndReason = "host_key_changed"
	EndTargetUnreachable EndReason = "target_unreachable"
	EndNetworkLost       EndReason = "network_lost"
	EndRevoked           EndReason = "revoked"
	EndExpired           EndReason = "expired"
	EndSlowConsumer      EndReason = "slow_consumer"
	EndServerShutdown    EndReason = "server_shutdown"
	EndHostRemoved       EndReason = "host_removed"
	EndProtocolError     EndReason = "protocol_error"
	EndOpenFailed        EndReason = "open_failed"
)

// Control is the single JSON shape for text frames. Fields are used according
// to Type; Parse enforces which ones are meaningful.
type Control struct {
	Type ControlType `json:"type"`

	HostID string `json:"hostId,omitempty"`
	Cols   int    `json:"cols,omitempty"`
	Rows   int    `json:"rows,omitempty"`
	Term   string `json:"term,omitempty"`

	SessionID string `json:"sessionId,omitempty"`
	// ExpiresAt is RFC 3339; the terminal is closed by the server at that time.
	ExpiresAt string `json:"expiresAt,omitempty"`

	Bytes int64 `json:"bytes,omitempty"`

	Reason     EndReason `json:"reason,omitempty"`
	Message    string    `json:"message,omitempty"`
	ExitStatus *int      `json:"exitStatus,omitempty"`
	Signal     string    `json:"signal,omitempty"`
}

// Viewport is a validated terminal size.
type Viewport struct{ Cols, Rows int }

func NewViewport(cols, rows int) (Viewport, error) {
	if cols < MinDimension || cols > MaxDimension || rows < MinDimension || rows > MaxDimension {
		return Viewport{}, fmt.Errorf("terminal size %dx%d out of range", cols, rows)
	}
	return Viewport{Cols: cols, Rows: rows}, nil
}

// DefaultTerm is used when a client sends no usable TERM value.
const DefaultTerm = "xterm-256color"

// SanitizeTerm accepts a conventional TERM name and falls back to DefaultTerm.
func SanitizeTerm(term string) string {
	if term == "" || len(term) > 64 {
		return DefaultTerm
	}
	for _, r := range term {
		if r > unicode.MaxASCII || !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '.' || r == '+' || r == '_') {
			return DefaultTerm
		}
	}
	return term
}

var ErrMalformed = errors.New("malformed control message")

// ParseClient parses a client -> server control frame.
func ParseClient(data []byte) (Control, error) {
	if len(data) > MaxControl {
		return Control{}, ErrMalformed
	}
	var c Control
	if err := json.Unmarshal(data, &c); err != nil {
		return Control{}, ErrMalformed
	}
	switch c.Type {
	case TypeOpen:
		if c.HostID == "" {
			return Control{}, ErrMalformed
		}
		if _, err := NewViewport(c.Cols, c.Rows); err != nil {
			return Control{}, err
		}
	case TypeResize:
		if _, err := NewViewport(c.Cols, c.Rows); err != nil {
			return Control{}, err
		}
	case TypeAck:
		if c.Bytes < 0 {
			return Control{}, ErrMalformed
		}
	case TypeClose:
	default:
		return Control{}, ErrMalformed
	}
	return c, nil
}

// ParseServer parses a server -> client control frame.
func ParseServer(data []byte) (Control, error) {
	var c Control
	if err := json.Unmarshal(data, &c); err != nil {
		return Control{}, ErrMalformed
	}
	switch c.Type {
	case TypeReady, TypeAck, TypeEnd:
		return c, nil
	}
	return Control{}, ErrMalformed
}

func Encode(c Control) []byte {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	return b
}

// Describe returns a short human-readable explanation of an end reason.
func Describe(r EndReason) string {
	switch r {
	case EndRemoteExit:
		return "remote shell exited"
	case EndClientClose:
		return "disconnected by client"
	case EndAuthFailed:
		return "target host rejected the saved credential"
	case EndHostKeyUnknown:
		return "target host key is not verified; verify it in the web UI"
	case EndHostKeyChanged:
		return "TARGET HOST KEY CHANGED; connection refused before sending credentials"
	case EndTargetUnreachable:
		return "target host unreachable from the gateway"
	case EndNetworkLost:
		return "connection to the gateway lost"
	case EndRevoked:
		return "access revoked"
	case EndExpired:
		return "credential expired; sign in again"
	case EndSlowConsumer:
		return "client stopped consuming output"
	case EndServerShutdown:
		return "gateway shutting down"
	case EndHostRemoved:
		return "host removed from the catalog"
	case EndProtocolError:
		return "protocol error"
	case EndOpenFailed:
		return "could not open the terminal"
	}
	return string(r)
}
