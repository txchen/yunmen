// Package cli implements the yunmen command-line client.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to one gateway. Access headers are sent on every request;
// the device token only when present.
type Client struct {
	Gateway *url.URL
	Secrets Secrets
	HTTP    *http.Client
}

func ParseGateway(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("gateway URL must look like https://yunmen.example.com")
	}
	if u.Scheme == "http" && !isLocal(u.Hostname()) {
		return nil, errors.New("refusing plain http to a non-local gateway; use https")
	}
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	return u, nil
}

func isLocal(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

func NewClient(gateway *url.URL, s Secrets) *Client {
	return &Client{Gateway: gateway, Secrets: s, HTTP: &http.Client{
		Timeout: 30 * time.Second,
		// Never forward credentials across redirects (Access login pages included).
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (c *Client) headers(h http.Header) {
	if c.Secrets.AccessClientID != "" {
		h.Set("CF-Access-Client-Id", c.Secrets.AccessClientID)
		h.Set("CF-Access-Client-Secret", c.Secrets.AccessClientSecret)
	}
	if c.Secrets.DeviceToken != "" {
		h.Set("Authorization", "Bearer "+c.Secrets.DeviceToken)
	}
}

// APIError is a non-2xx response.
type APIError struct {
	Status int
	Msg    string
}

func (e *APIError) Error() string { return e.Msg }

// NeedsAccessToken reports whether a request was stopped by Cloudflare
// Access: Access redirects to its login page or Yunmen in access mode
// answers 403. A standalone gateway never answers pairing that way.
func NeedsAccessToken(err error) bool {
	var e *APIError
	return errors.As(err, &e) && (e.Status == http.StatusForbidden || e.Status >= 300 && e.Status < 400)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Gateway.String()+path, body)
	if err != nil {
		return err
	}
	c.headers(req.Header)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach gateway %s: %w", c.Gateway.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return describeHTTPError(resp)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

func describeHTTPError(resp *http.Response) error {
	var e struct {
		Error string `json:"error"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	json.Unmarshal(b, &e)
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return &APIError{resp.StatusCode, "gateway redirected the request (likely a Cloudflare Access login page): check the service token Client ID/Secret and the Access Service Auth policy"}
	case e.Error != "":
		return &APIError{resp.StatusCode, e.Error}
	case resp.StatusCode == http.StatusForbidden:
		return &APIError{resp.StatusCode, "forbidden by Cloudflare Access: check the service token and the Service Auth policy"}
	}
	return &APIError{resp.StatusCode, fmt.Sprintf("gateway returned HTTP %d", resp.StatusCode)}
}

type Host struct {
	ID       string `json:"id"`
	Alias    string `json:"alias"`
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Username string `json:"username"`
}

func (c *Client) Hosts(ctx context.Context) ([]Host, error) {
	var hs []Host
	return hs, c.do(ctx, http.MethodGet, "/api/v1/cli/hosts", nil, &hs)
}

func (c *Client) Logout(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/v1/cli/logout", nil, nil)
}

type PairStart struct {
	PollToken  string    `json:"pollToken"`
	UserCode   string    `json:"userCode"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Interval   int       `json:"interval"`
	ApproveURL string    `json:"approveUrl"`
}

type PairPoll struct {
	Status      string `json:"status"`
	DeviceID    string `json:"deviceId"`
	DeviceToken string `json:"deviceToken"`
	ExpiresAt   string `json:"expiresAt"`
	Label       string `json:"label"`
}

func (c *Client) PairStart(ctx context.Context, label string) (PairStart, error) {
	var p PairStart
	return p, c.do(ctx, http.MethodPost, "/api/v1/cli/pair/start", map[string]string{"label": label}, &p)
}

func (c *Client) PairPoll(ctx context.Context, token string) (PairPoll, error) {
	var p PairPoll
	return p, c.do(ctx, http.MethodPost, "/api/v1/cli/pair/poll", map[string]string{"pollToken": token}, &p)
}
