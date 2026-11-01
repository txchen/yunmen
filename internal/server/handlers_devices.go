package server

import (
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/txchen/yunmen/internal/live"
	"github.com/txchen/yunmen/internal/protocol"
	"github.com/txchen/yunmen/internal/terminal"
)

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request, _ ownerCtx) {
	devices, err := s.store.ListDevices(r.Context())
	if err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]map[string]any, 0, len(devices))
	now := s.now()
	for _, d := range devices {
		status := "active"
		switch {
		case d.RevokedAt != nil:
			status = "revoked"
		case !now.Before(d.ExpiresAt):
			status = "expired"
		}
		out = append(out, map[string]any{
			"id": d.ID, "label": d.Label, "servicePrincipal": d.ServicePrincipal,
			"authorizedAt": d.CreatedAt, "expiresAt": d.ExpiresAt, "lastUsedAt": d.LastUsedAt, "revokedAt": d.RevokedAt,
			"status": status, "activeTerminals": s.reg.Count(live.DeviceCredential(d.ID)),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// revokeDevice commits the revocation, then ends that device's terminals.
func (s *Server) revokeDevice(r *http.Request, id string) (int, error) {
	if err := s.store.RevokeDevice(r.Context(), id); err != nil {
		return 0, err
	}
	n := s.reg.RevokeCredential(live.DeviceCredential(id), protocol.EndRevoked)
	s.log.Info("device revoked", "device", id, "closed_terminals", n)
	return n, nil
}

func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request, _ ownerCtx) {
	n, err := s.revokeDevice(r, r.PathValue("id"))
	if err != nil {
		httpError(w, statusFor(err), "device not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"closedTerminals": n})
}

func (s *Server) handleCLILogout(w http.ResponseWriter, r *http.Request, d deviceCtx) {
	if _, err := s.revokeDevice(r, d.device.ID); err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleCLIDevice(w http.ResponseWriter, r *http.Request, d deviceCtx) {
	writeJSON(w, http.StatusOK, d.device)
}

func cleanLabel(l string) string {
	l = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(l))
	if l == "" {
		l = "unnamed device"
	}
	for utf8.RuneCountInString(l) > 64 {
		_, size := utf8.DecodeLastRuneInString(l)
		l = l[:len(l)-size]
	}
	return l
}

func (s *Server) handlePairStart(w http.ResponseWriter, r *http.Request, acc accessIdentity) {
	var req struct {
		Label string `json:"label"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	token, p, ok := s.pairings.start(cleanLabel(req.Label), acc.subject)
	if !ok {
		httpError(w, http.StatusTooManyRequests, "too many pending device approvals; wait a few minutes")
		return
	}
	s.log.Info("device pairing started", "label", p.label, "principal", p.principal)
	writeJSON(w, http.StatusOK, map[string]any{
		"pollToken": token, "userCode": p.userCode, "expiresAt": p.expires,
		"interval": int(pairPollInterval / time.Second), "approveUrl": s.cfg.OriginString() + "/approve",
	})
}

func (s *Server) handlePairPoll(w http.ResponseWriter, r *http.Request, acc accessIdentity) {
	var req struct {
		PollToken string `json:"pollToken"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	res, p := s.pairings.poll(req.PollToken, acc.subject)
	if res != pollApproved {
		writeJSON(w, http.StatusOK, map[string]any{"status": res})
		return
	}
	raw, d, err := s.store.CreateDevice(r.Context(), p.label, p.principal)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.log.Info("device approved", "device", d.ID, "label", d.Label)
	writeJSON(w, http.StatusOK, map[string]any{"status": res, "deviceId": d.ID, "deviceToken": raw, "expiresAt": d.ExpiresAt, "label": d.Label})
}

type codeRequest struct {
	UserCode string `json:"userCode"`
}

func (s *Server) handlePairLookup(w http.ResponseWriter, r *http.Request, _ ownerCtx) {
	var req codeRequest
	if !readJSON(w, r, &req) {
		return
	}
	p, ok := s.pairings.lookup(req.UserCode)
	if !ok {
		httpError(w, http.StatusNotFound, "no pending request with that code (it may have expired)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"userCode": p.userCode, "label": p.label, "requestedAt": p.created, "expiresAt": p.expires, "servicePrincipal": p.principal})
}

func (s *Server) handlePairApprove(w http.ResponseWriter, r *http.Request, _ ownerCtx) {
	var req struct {
		UserCode string `json:"userCode"`
		ownerProof
	}
	if !readJSON(w, r, &req) {
		return
	}
	if _, ok := s.pairings.lookup(req.UserCode); !ok {
		httpError(w, http.StatusNotFound, "no pending request with that code (it may have expired)")
		return
	}
	if status, msg := s.verifyOwner(r, req.ownerProof); status != 0 {
		httpError(w, status, msg)
		return
	}
	if _, ok := s.pairings.decide(req.UserCode, true); !ok {
		httpError(w, http.StatusNotFound, "no pending request with that code (it may have expired)")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePairDeny(w http.ResponseWriter, r *http.Request, _ ownerCtx) {
	var req codeRequest
	if !readJSON(w, r, &req) {
		return
	}
	s.pairings.decide(req.UserCode, false)
	w.WriteHeader(http.StatusNoContent)
}

// handleTerminal authenticates the upgrade before any SSH resource exists.
// CLI upgrades carry a bearer device token; browser upgrades carry the
// session cookie and must come from the configured origin.
func (s *Server) handleTerminal(w http.ResponseWriter, r *http.Request) {
	var p terminal.Principal
	if bearer(r) != "" {
		if r.Header.Get("Origin") != "" {
			httpError(w, http.StatusForbidden, "bearer terminals must not come from a browser origin")
			return
		}
		d, status, msg := s.authDevice(r)
		if status != 0 {
			httpError(w, status, msg)
			return
		}
		p = terminal.Principal{Cred: d.cred, Deadline: d.deadline}
	} else {
		if !s.sameOrigin(r) {
			httpError(w, http.StatusForbidden, "cross-origin terminal rejected")
			return
		}
		o, status, msg := s.authOwner(r)
		if status != 0 {
			httpError(w, status, msg)
			return
		}
		p = terminal.Principal{Cred: o.cred, Deadline: o.deadline}
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.Subprotocol}, InsecureSkipVerify: true})
	if err != nil {
		return
	}
	if conn.Subprotocol() != protocol.Subprotocol {
		conn.Close(websocket.StatusPolicyViolation, "unsupported protocol version; upgrade the client")
		return
	}
	terminal.Serve(r.Context(), conn, p, s.termDeps)
}
