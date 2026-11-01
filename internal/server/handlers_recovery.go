package server

import (
	"net/http"
	"sync"
	"time"

	"github.com/txchen/yunmen/internal/auth"
	"github.com/txchen/yunmen/internal/store"
)

const recoveryTTL = 10 * time.Minute

// recoveryChallenge is a pending authenticator replacement. The recovery
// code is used up only when the new authenticator is confirmed.
type recoveryChallenge struct {
	recoveryCode string
	secret       []byte
	expires      time.Time
}

type recoveries struct {
	mu   sync.Mutex
	byID map[string]recoveryChallenge
	now  func() time.Time
}

func newRecoveries() *recoveries {
	return &recoveries{byID: map[string]recoveryChallenge{}, now: time.Now}
}

func (r *recoveries) add(c recoveryChallenge) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, v := range r.byID {
		if r.now().After(v.expires) {
			delete(r.byID, id)
		}
	}
	id := store.NewID()
	r.byID[id] = c
	return id
}

func (r *recoveries) get(id string) (recoveryChallenge, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok || r.now().After(c.expires) {
		return recoveryChallenge{}, false
	}
	return c, true
}

func (r *recoveries) drop(id string) {
	r.mu.Lock()
	delete(r.byID, id)
	r.mu.Unlock()
}

// limited runs check under both login rate limiters. check reports failure
// by returning http.StatusUnauthorized.
// Reservations are released in a defer so a panic in check cannot leak them.
func (s *Server) limited(r *http.Request, check func() (int, string)) (status int, text string) {
	const msg = "too many failed attempts; wait a few minutes"
	doneClient, ok := s.perClient.reserve(s.clientKey(r))
	if !ok {
		return http.StatusTooManyRequests, msg
	}
	doneGlobal, ok := s.global.reserve("owner")
	if !ok {
		doneClient(false)
		return http.StatusTooManyRequests, msg
	}
	defer func() {
		failed := status == http.StatusUnauthorized
		doneClient(failed)
		doneGlobal(failed)
	}()
	return check()
}

func (s *Server) handleRecoveryStart(w http.ResponseWriter, r *http.Request, _ accessIdentity) {
	var req struct {
		Password     string `json:"password"`
		RecoveryCode string `json:"recoveryCode"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	status, msg := s.limited(r, func() (int, string) {
		owner, err := s.store.Owner(r.Context())
		if err != nil {
			return http.StatusServiceUnavailable, "owner not initialized"
		}
		okPass, err := auth.VerifyPassword(owner.PasswordHash, req.Password)
		if err != nil {
			s.log.Error("password hash unreadable", "err", err)
			return http.StatusInternalServerError, "internal error"
		}
		okCode, err := s.store.RecoveryCodeUnused(r.Context(), req.RecoveryCode)
		if err != nil {
			return http.StatusInternalServerError, "internal error"
		}
		if !okPass || !okCode {
			return http.StatusUnauthorized, "incorrect password or recovery code"
		}
		return 0, ""
	})
	if status != 0 {
		httpError(w, status, msg)
		return
	}
	secret := auth.NewTOTPSecret()
	exp := s.now().Add(recoveryTTL)
	id := s.recoveries.add(recoveryChallenge{recoveryCode: req.RecoveryCode, secret: secret, expires: exp})
	s.log.Warn("authenticator recovery started")
	writeJSON(w, http.StatusOK, map[string]any{"challengeId": id, "secret": auth.TOTPBase32(secret),
		"otpauthUri": auth.TOTPURI(secret, "owner"), "expiresAt": exp})
}

func (s *Server) handleRecoveryFinish(w http.ResponseWriter, r *http.Request, _ accessIdentity) {
	var req struct {
		ChallengeID string `json:"challengeId"`
		Code        string `json:"code"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	c, ok := s.recoveries.get(req.ChallengeID)
	if !ok {
		httpError(w, http.StatusGone, "recovery expired; start again")
		return
	}
	var step int64
	status, msg := s.limited(r, func() (int, string) {
		var match bool
		if step, match = auth.MatchTOTP(c.secret, req.Code, s.now()); !match {
			return http.StatusUnauthorized, "code does not match the new authenticator; check the device clock"
		}
		return 0, ""
	})
	if status != 0 {
		httpError(w, status, msg)
		return
	}
	used, err := s.store.RecoverWithCode(r.Context(), c.recoveryCode, c.secret, step)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.recoveries.drop(req.ChallengeID)
	if !used {
		httpError(w, http.StatusGone, "this recovery code was already used")
		return
	}
	s.SweepRevoked(r.Context())
	s.log.Warn("authenticator replaced with a recovery code; all sessions and devices revoked")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request, _ ownerCtx) {
	var p ownerProof
	if !readJSON(w, r, &p) {
		return
	}
	if status, msg := s.verifyOwner(r, p); status != 0 {
		httpError(w, status, msg)
		return
	}
	codes, err := s.store.ReplaceRecoveryCodes(r.Context())
	if err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.log.Info("recovery codes regenerated")
	writeJSON(w, http.StatusOK, map[string]any{"codes": codes})
}
