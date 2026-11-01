package server

import (
	"net"
	"net/http"
	"strings"

	"github.com/txchen/yunmen/internal/auth"
	"github.com/txchen/yunmen/internal/live"
	"github.com/txchen/yunmen/internal/protocol"
)

type ownerProof struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

// clientKey identifies the caller for rate limiting. The visitor address
// header is trusted only when configured (YUNMEN_CLIENT_IP_HEADER), or in
// access mode, where every request has passed Cloudflare. Otherwise a
// client could pick a fresh address for every guess.
func (s *Server) clientKey(r *http.Request) string {
	header := s.cfg.ClientIPHeader
	if header == "" && s.access != nil {
		header = "Cf-Connecting-IP"
	}
	if header != "" {
		// A proxy that appends (X-Forwarded-For) puts its own view last.
		values := strings.Split(r.Header.Get(header), ",")
		if ip := net.ParseIP(strings.TrimSpace(values[len(values)-1])); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// verifyOwner checks password and TOTP together and consumes the TOTP step.
// It reveals nothing about which factor failed.
func (s *Server) verifyOwner(r *http.Request, p ownerProof) (int, string) {
	return s.limited(r, func() (int, string) {
		ctx := r.Context()
		owner, err := s.store.Owner(ctx)
		if err != nil {
			s.log.Error("load owner", "err", err)
			return http.StatusServiceUnavailable, "owner not initialized; run `yunmen-server init` on the server"
		}
		okPass, err := auth.VerifyPassword(owner.PasswordHash, p.Password)
		if err != nil {
			s.log.Error("password hash unreadable", "err", err)
			return http.StatusInternalServerError, "internal error"
		}
		step, okCode := auth.MatchTOTP(owner.TOTPSecret, p.Code, s.now())
		if !okPass || !okCode {
			return http.StatusUnauthorized, "incorrect password or authentication code"
		}
		fresh, err := s.store.AcceptTOTPStep(ctx, step)
		if err != nil {
			return http.StatusInternalServerError, "internal error"
		}
		if !fresh {
			return http.StatusUnauthorized, "authentication code already used; wait for the next code"
		}
		return 0, ""
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, _ accessIdentity) {
	var p ownerProof
	if !readJSON(w, r, &p) {
		return
	}
	if status, msg := s.verifyOwner(r, p); status != 0 {
		httpError(w, status, msg)
		return
	}
	raw, ws, err := s.store.CreateWebSession(r.Context())
	if err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: raw, Path: "/", Expires: ws.ExpiresAt,
		HttpOnly: true, Secure: s.cfg.SecureCookies(), SameSite: http.SameSiteStrictMode})
	s.log.Info("owner signed in")
	writeJSON(w, http.StatusOK, map[string]any{"expiresAt": ws.ExpiresAt})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, o ownerCtx) {
	if err := s.store.RevokeWebSession(r.Context(), o.session.ID); err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.reg.RevokeCredential(live.WebCredential(o.session.ID), protocol.EndRevoked)
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.SecureCookies(), SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request, o ownerCtx) {
	remaining, err := s.store.RecoveryCodesRemaining(r.Context())
	if err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"expiresAt": o.session.ExpiresAt, "mode": s.cfg.Mode, "recoveryCodesRemaining": remaining})
}
