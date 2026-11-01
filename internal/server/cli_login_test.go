package server

import (
	"context"
	"net/url"
	"testing"

	"github.com/txchen/yunmen/internal/auth"
	"github.com/txchen/yunmen/internal/cli"
)

// yunmen login asks for an Access service token only when the gateway
// turns away a pairing request without one.
func TestCLILoginAsksForServiceTokenOnlyBehindAccess(t *testing.T) {
	ctx := context.Background()

	standalone := newHarness(t, ModeStandalone)
	gw, _ := url.Parse(standalone.http.URL)
	if _, err := cli.NewClient(gw, cli.Secrets{}).PairStart(ctx, "laptop"); err != nil || cli.NeedsAccessToken(err) {
		t.Fatalf("standalone pairing without a token: %v", err)
	}

	access := newHarness(t, ModeAccess)
	gw, _ = url.Parse(access.http.URL)
	_, err := cli.NewClient(gw, cli.Secrets{}).PairStart(ctx, "laptop")
	if !cli.NeedsAccessToken(err) {
		t.Fatalf("access mode without a token: %v", err)
	}
	withToken := cli.NewClient(gw, cli.Secrets{AccessClientID: serviceID, AccessClientSecret: "s"})
	// Cloudflare would mint the assertion from the Client ID/Secret.
	withToken.HTTP.Transport = headerTransport{auth.AccessHeader: access.access.service(t, serviceID)}
	if _, err := withToken.PairStart(ctx, "laptop"); err != nil {
		t.Fatalf("access mode with a token: %v", err)
	}
}
