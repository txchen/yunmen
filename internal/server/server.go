// Package server is the HTTP boundary: it authenticates every request through
// Cloudflare Access (in access mode) plus Yunmen's own credentials, then calls
// the domain packages.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/txchen/yunmen/internal/auth"
	"github.com/txchen/yunmen/internal/files"
	"github.com/txchen/yunmen/internal/live"
	"github.com/txchen/yunmen/internal/protocol"
	"github.com/txchen/yunmen/internal/store"
	"github.com/txchen/yunmen/internal/terminal"
)

type Server struct {
	cfg       Config
	store     *store.Store
	reg       *live.Registry
	access    *auth.AccessVerifier // nil in standalone mode
	log       *slog.Logger
	perClient *limiter // failed owner-credential checks per client address
	global    *limiter // and across all clients, for the single owner
	pairings  *pairings
	probes    *observations
	files     *files.Service
	web       fs.FS
	termDeps  terminal.Deps
	now       func() time.Time
}

type Options struct {
	Config   Config
	Store    *store.Store
	Access   *auth.AccessVerifier
	Log      *slog.Logger
	Web      fs.FS
	Terminal terminal.Deps // optional timing overrides (tests)
}

func New(o Options) *Server {
	reg := live.New()
	s := &Server{cfg: o.Config, store: o.Store, reg: reg, access: o.Access, log: o.Log, web: o.Web, now: time.Now,
		perClient: newLimiter(5, 5*time.Minute), global: newLimiter(20, 5*time.Minute), pairings: newPairings(), probes: newObservations()}
	s.files = files.New(o.Store, reg, o.Log)
	s.termDeps = o.Terminal
	s.termDeps.Store, s.termDeps.Registry, s.termDeps.Log = o.Store, reg, o.Log
	return s
}

// Registry is exposed for shutdown and tests.
func (s *Server) Registry() *live.Registry { return s.reg }

// Files is exposed for startup cleanup.
func (s *Server) Files() *files.Service { return s.files }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })

	mux.HandleFunc("POST /api/v1/auth/login", s.withAccess(auth.PrincipalOwner, s.handleLogin))
	mux.HandleFunc("POST /api/v1/auth/logout", s.owner(s.handleLogout))
	mux.HandleFunc("GET /api/v1/auth/session", s.owner(s.handleSession))

	mux.HandleFunc("GET /api/v1/hosts", s.owner(s.handleListHosts))
	mux.HandleFunc("POST /api/v1/hosts/probe", s.owner(s.handleProbe))
	mux.HandleFunc("POST /api/v1/hosts", s.owner(s.handleCreateHost))
	mux.HandleFunc("PUT /api/v1/hosts/{id}", s.owner(s.handleUpdateHost))
	mux.HandleFunc("DELETE /api/v1/hosts/{id}", s.owner(s.handleDeleteHost))

	mux.HandleFunc("GET /api/v1/devices", s.owner(s.handleListDevices))
	mux.HandleFunc("POST /api/v1/devices/{id}/revoke", s.owner(s.handleRevokeDevice))
	mux.HandleFunc("POST /api/v1/pairings/lookup", s.owner(s.handlePairLookup))
	mux.HandleFunc("POST /api/v1/pairings/approve", s.owner(s.handlePairApprove))
	mux.HandleFunc("POST /api/v1/pairings/deny", s.owner(s.handlePairDeny))

	mux.HandleFunc("GET /api/v1/hosts/{id}/files", s.owner(s.handleListFiles))
	mux.HandleFunc("GET /api/v1/hosts/{id}/download", s.owner(s.handleDownload))
	mux.HandleFunc("POST /api/v1/hosts/{id}/uploads", s.owner(s.handleBeginUpload))
	mux.HandleFunc("PUT /api/v1/uploads/{id}", s.owner(s.handleUploadChunk))
	mux.HandleFunc("POST /api/v1/uploads/{id}/commit", s.owner(s.handleCommitUpload))
	mux.HandleFunc("DELETE /api/v1/uploads/{id}", s.owner(s.handleCancelUpload))

	mux.HandleFunc("POST /api/v1/cli/pair/start", s.withAccess(auth.PrincipalService, s.handlePairStart))
	mux.HandleFunc("POST /api/v1/cli/pair/poll", s.withAccess(auth.PrincipalService, s.handlePairPoll))
	mux.HandleFunc("GET /api/v1/cli/hosts", s.device(s.handleCLIHosts))
	mux.HandleFunc("GET /api/v1/cli/device", s.device(s.handleCLIDevice))
	mux.HandleFunc("POST /api/v1/cli/logout", s.device(s.handleCLILogout))

	mux.HandleFunc("GET /api/v1/terminal", s.handleTerminal)

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { httpError(w, http.StatusNotFound, "not found") })
	mux.HandleFunc("/", s.withAccess(0, s.handleStatic))
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			hd.Set("Cache-Control", "no-store")
		}
		h.ServeHTTP(w, r)
	})
}

// accessIdentity is the outer layer. In standalone mode it admits every
// request with no deadline of its own; in access mode a valid assertion of the
// wanted principal kind is mandatory (want 0 accepts either kind).
type accessIdentity struct {
	subject   string
	expiresAt time.Time
}

var farFuture = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

func (s *Server) checkAccess(r *http.Request, want auth.PrincipalKind) (accessIdentity, error) {
	if s.access == nil {
		subject := ""
		if want == auth.PrincipalService {
			subject = StandalonePrincipal
		}
		return accessIdentity{subject: subject, expiresAt: farFuture}, nil
	}
	id, err := s.access.Verify(r.Context(), r.Header.Get(auth.AccessHeader))
	if err != nil {
		return accessIdentity{}, err
	}
	if want != 0 && id.Kind != want {
		return accessIdentity{}, auth.ErrAccessDenied
	}
	return accessIdentity{subject: id.Subject, expiresAt: id.ExpiresAt}, nil
}

type accessHandler func(http.ResponseWriter, *http.Request, accessIdentity)

func (s *Server) withAccess(want auth.PrincipalKind, h accessHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := s.checkAccess(r, want)
		if err != nil {
			s.log.Warn("access assertion rejected", "path", r.URL.Path, "err", err)
			httpError(w, http.StatusForbidden, "cloudflare access assertion missing or invalid")
			return
		}
		if want == auth.PrincipalOwner && r.Method != http.MethodGet && !s.sameOrigin(r) {
			httpError(w, http.StatusForbidden, "cross-origin request rejected")
			return
		}
		h(w, r, id)
	}
}

func (s *Server) sameOrigin(r *http.Request) bool {
	return r.Header.Get("Origin") == s.cfg.OriginString()
}

// ownerCtx is an authenticated owner browser session.
type ownerCtx struct {
	session  store.WebSession
	cred     live.Credential
	deadline time.Time
}

type ownerHandler func(http.ResponseWriter, *http.Request, ownerCtx)

func (s *Server) cookieName() string {
	if s.cfg.SecureCookies() {
		return "__Host-yunmen_session"
	}
	return "yunmen_session"
}

func (s *Server) authOwner(r *http.Request) (ownerCtx, int, string) {
	acc, err := s.checkAccess(r, auth.PrincipalOwner)
	if err != nil {
		return ownerCtx{}, http.StatusForbidden, "cloudflare access assertion missing or invalid"
	}
	c, err := r.Cookie(s.cookieName())
	if err != nil {
		return ownerCtx{}, http.StatusUnauthorized, "sign in required"
	}
	ws, err := s.store.LookupWebSession(r.Context(), c.Value)
	if err != nil {
		return ownerCtx{}, http.StatusUnauthorized, "session expired or revoked; sign in again"
	}
	return ownerCtx{session: ws, cred: live.WebCredential(ws.ID), deadline: earliest(ws.ExpiresAt, acc.expiresAt)}, 0, ""
}

func (s *Server) owner(h ownerHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && !s.sameOrigin(r) {
			httpError(w, http.StatusForbidden, "cross-origin request rejected")
			return
		}
		o, status, msg := s.authOwner(r)
		if status != 0 {
			httpError(w, status, msg)
			return
		}
		h(w, r, o)
	}
}

// deviceCtx is an authenticated CLI device: Access service principal plus the
// Yunmen device token bound to that principal.
type deviceCtx struct {
	device   store.Device
	cred     live.Credential
	deadline time.Time
}

type deviceHandler func(http.ResponseWriter, *http.Request, deviceCtx)

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *Server) authDevice(r *http.Request) (deviceCtx, int, string) {
	acc, err := s.checkAccess(r, auth.PrincipalService)
	if err != nil {
		return deviceCtx{}, http.StatusForbidden, "cloudflare access service token missing or invalid"
	}
	tok := bearer(r)
	if tok == "" {
		return deviceCtx{}, http.StatusUnauthorized, "device token required; run `yunmen login`"
	}
	d, err := s.store.LookupDevice(r.Context(), tok)
	if err != nil {
		return deviceCtx{}, http.StatusUnauthorized, "device token expired or revoked; run `yunmen login`"
	}
	if d.ServicePrincipal != acc.subject {
		return deviceCtx{}, http.StatusUnauthorized, "device token is bound to a different service token"
	}
	return deviceCtx{device: d, cred: live.DeviceCredential(d.ID), deadline: earliest(d.ExpiresAt, acc.expiresAt)}, 0, ""
}

func (s *Server) device(h deviceHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, status, msg := s.authDevice(r)
		if status != 0 {
			httpError(w, status, msg)
			return
		}
		h(w, r, d)
	}
}

func earliest(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func httpError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// readJSON decodes a bounded JSON body, rejecting unknown fields.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		httpError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

// Shutdown ends every live terminal and transfer.
func (s *Server) Shutdown(ctx context.Context) { s.reg.Shutdown() }

func statusFor(err error) int {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrAliasTaken):
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}

// SweepRevoked ends live operations whose credential was revoked outside
// this process (local recovery commands) or expired in the database.
func (s *Server) SweepRevoked(ctx context.Context) {
	for _, cred := range s.reg.Credentials() {
		kind, id := cred.Split()
		ok, err := s.store.CredentialActive(ctx, kind, id)
		if err == nil && !ok {
			n := s.reg.RevokeCredential(cred, protocol.EndRevoked)
			s.log.Info("ended operations of a revoked credential", "kind", kind, "closed", n)
		}
	}
}

// RunSweeper calls SweepRevoked every interval until ctx ends.
func (s *Server) RunSweeper(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.SweepRevoked(ctx)
		}
	}
}
