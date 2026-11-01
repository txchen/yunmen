package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestStartPairing(t *testing.T) {
	for _, tc := range []struct {
		name        string
		access      bool
		retryStatus int
		cancel      bool
	}{
		{name: "standalone"},
		{name: "access", access: true, retryStatus: 200},
		{name: "rejected token", access: true, retryStatus: 403},
		{name: "cancelled prompt", access: true, cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.access {
					if r.Header.Get("CF-Access-Client-Id") != "test-id" || r.Header.Get("CF-Access-Client-Secret") != "test-secret" {
						http.Error(w, "token required", 403)
						return
					}
					if tc.retryStatus != 200 {
						w.WriteHeader(tc.retryStatus)
						return
					}
				}
				w.Write([]byte(`{"userCode":"ABCD-EFGH","pollToken":"test-poll"}`))
			}))
			defer srv.Close()
			gw, _ := url.Parse(srv.URL)
			c := NewClient(gw, Secrets{})
			prompted := false
			cancelled := errors.New("cancelled")
			start, err := startPairing(context.Background(), c, "laptop", func() (Secrets, error) {
				prompted = true
				if tc.cancel {
					return Secrets{}, cancelled
				}
				return Secrets{AccessClientID: "test-id", AccessClientSecret: "test-secret"}, nil
			})
			if prompted != tc.access {
				t.Fatalf("prompted = %v", prompted)
			}
			switch {
			case tc.cancel:
				if !errors.Is(err, cancelled) {
					t.Fatalf("error = %v", err)
				}
			case tc.access && tc.retryStatus != 200:
				if !NeedsAccessToken(err) {
					t.Fatalf("error = %v", err)
				}
			default:
				if err != nil || start.UserCode != "ABCD-EFGH" {
					t.Fatalf("start = %+v, error = %v", start, err)
				}
			}
		})
	}
}
