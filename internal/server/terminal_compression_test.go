package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/txchen/yunmen/internal/protocol"
)

func TestTerminalCompressionNegotiation(t *testing.T) {
	h := newHarness(t, ModeStandalone)
	owner := h.browser()
	owner.login()
	for _, compressed := range []bool{false, true} {
		name := "uncompressed"
		mode := websocket.CompressionDisabled
		if compressed {
			name = "compressed"
			mode = websocket.CompressionNoContextTakeover
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, resp, err := websocket.Dial(ctx, wsURL(h), &websocket.DialOptions{
				HTTPHeader: owner.wsHeaders(), Subprotocols: []string{protocol.Subprotocol},
				CompressionMode: mode, CompressionThreshold: 1024,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseNow()
			ext := resp.Header.Get("Sec-WebSocket-Extensions")
			if !compressed {
				if ext != "" {
					t.Fatalf("unexpected extension: %s", ext)
				}
				return
			}
			for _, want := range []string{"permessage-deflate", "server_no_context_takeover", "client_no_context_takeover"} {
				if !strings.Contains(ext, want) {
					t.Fatalf("extension %q missing %q", ext, want)
				}
			}
		})
	}
}
