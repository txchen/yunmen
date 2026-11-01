package server

import (
	"errors"
	"net/http"

	"github.com/txchen/yunmen/internal/sshconn"
	"github.com/txchen/yunmen/internal/store"
)

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request, _ ownerCtx) {
	keys, err := s.store.ListKeys(r.Context())
	if err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request, _ ownerCtx) {
	var req struct {
		Label      string `json:"label"`
		Generate   bool   `json:"generate"`
		PrivateKey string `json:"privateKey"`
		Passphrase string `json:"passphrase"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	label, err := store.ParseKeyLabel(req.Label)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	var m store.KeyMaterial
	switch {
	case req.Generate && req.PrivateKey == "":
		m, err = sshconn.GenerateKey()
	case !req.Generate && req.PrivateKey != "":
		m, err = sshconn.ImportPrivateKey([]byte(req.PrivateKey), req.Passphrase)
		if err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
	default:
		httpError(w, http.StatusBadRequest, "send either generate: true or privateKey")
		return
	}
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not create the key")
		return
	}
	k, err := s.store.CreateKey(r.Context(), label, m)
	if errors.Is(err, store.ErrKeyExists) {
		httpError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.log.Info("key added", "key", k.ID, "type", k.Type, "generated", req.Generate)
	writeJSON(w, http.StatusCreated, k)
}

func (s *Server) handleRenameKey(w http.ResponseWriter, r *http.Request, _ ownerCtx) {
	var req struct {
		Label string `json:"label"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	label, err := store.ParseKeyLabel(req.Label)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	k, err := s.store.RenameKey(r.Context(), r.PathValue("id"), label)
	if err != nil {
		httpError(w, statusFor(err), "key not found")
		return
	}
	writeJSON(w, http.StatusOK, k)
}

// handleDeleteKey refuses keys that hosts use. Deleting also ends sessions
// still authenticated with the key (a host may have switched away from it
// while a terminal stayed open).
func (s *Server) handleDeleteKey(w http.ResponseWriter, r *http.Request, _ ownerCtx) {
	id := r.PathValue("id")
	users, err := s.store.DeleteKey(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrKeyInUse):
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "usedBy": users})
		return
	case err != nil:
		httpError(w, statusFor(err), "key not found")
		return
	}
	n := s.reg.RemoveKey(id)
	s.log.Info("key deleted", "key", id, "closed_sessions", n)
	w.WriteHeader(http.StatusNoContent)
}
