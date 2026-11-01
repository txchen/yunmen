package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/txchen/yunmen/internal/files"
	"github.com/txchen/yunmen/internal/protocol"
	"github.com/txchen/yunmen/internal/sshconn"
	"github.com/txchen/yunmen/internal/store"
	"golang.org/x/crypto/ssh"
)

type hostView struct {
	store.Host
	HostKeyType        string `json:"hostKeyType"`
	HostKeyFingerprint string `json:"hostKeyFingerprint"`
}

func viewHost(h store.Host) hostView {
	v := hostView{Host: h}
	if k, err := ssh.ParsePublicKey(h.HostKey); err == nil {
		v.HostKeyType, v.HostKeyFingerprint = k.Type(), ssh.FingerprintSHA256(k)
	}
	return v
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request, _ ownerCtx) {
	hosts, err := s.store.ListHosts(r.Context())
	if err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]hostView, len(hosts))
	for i, h := range hosts {
		out[i] = viewHost(h)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request, _ ownerCtx) {
	var req struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	spec, err := store.ParseHostSpec("probe", "", req.Address, "probe", req.Port)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	key, err := sshconn.Probe(r.Context(), spec.Endpoint())
	if err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	id, exp := s.probes.add(spec.Endpoint(), key)
	writeJSON(w, http.StatusOK, map[string]any{"observationId": id, "endpoint": spec.Endpoint(),
		"keyType": key.Type(), "fingerprint": ssh.FingerprintSHA256(key), "expiresAt": exp})
}

type authInput struct {
	Kind       store.AuthKind `json:"kind"`
	PrivateKey string         `json:"privateKey"`
	Passphrase string         `json:"passphrase"`
	Password   string         `json:"password"`
}

type hostInput struct {
	Alias         string     `json:"alias"`
	Name          string     `json:"name"`
	Address       string     `json:"address"`
	Port          int        `json:"port"`
	Username      string     `json:"username"`
	Auth          *authInput `json:"auth"`
	ObservationID string     `json:"observationId"`
	Revision      int64      `json:"revision"`
}

func parseCredential(a authInput) (store.Credential, string, error) {
	switch a.Kind {
	case store.AuthKey:
		pemBytes, fp, err := sshconn.ImportPrivateKey([]byte(a.PrivateKey), a.Passphrase)
		if err != nil {
			return store.Credential{}, "", err
		}
		return store.Credential{Kind: store.AuthKey, PrivateKey: pemBytes}, fp, nil
	case store.AuthPassword:
		if a.Password == "" || len(a.Password) > 1024 {
			return store.Credential{}, "", errors.New("password must be 1-1024 bytes")
		}
		return store.Credential{Kind: store.AuthPassword, Password: a.Password}, "", nil
	}
	return store.Credential{}, "", errors.New("auth.kind must be `key` or `password`")
}

// testConnection authenticates with the candidate settings before they are
// saved and reports whether SFTP is available.
func testConnection(ctx context.Context, spec store.HostSpec, hostKey []byte, cred store.Credential) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	h := store.Host{Address: spec.Address, Port: spec.Port, Username: spec.Username, HostKey: hostKey}
	client, err := sshconn.Dial(ctx, h, cred)
	if err != nil {
		return false, err
	}
	defer client.Close()
	return files.Available(client), nil
}

func connectionError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	if sshconn.ReasonOf(err) == protocol.EndAuthFailed {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, map[string]string{"error": err.Error(), "reason": string(sshconn.ReasonOf(err))})
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request, _ ownerCtx) {
	var in hostInput
	if !readJSON(w, r, &in) {
		return
	}
	spec, err := store.ParseHostSpec(in.Alias, in.Name, in.Address, in.Username, in.Port)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Auth == nil {
		httpError(w, http.StatusBadRequest, "auth is required")
		return
	}
	cred, fp, err := parseCredential(*in.Auth)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	key, ok := s.probes.get(in.ObservationID, spec.Endpoint())
	if !ok {
		httpError(w, http.StatusBadRequest, "verify the host key first (probe expired or does not match this address and port)")
		return
	}
	sftpOK, err := testConnection(r.Context(), spec, key.Marshal(), cred)
	if err != nil {
		connectionError(w, err)
		return
	}
	h, err := s.store.CreateHost(r.Context(), spec, key.Marshal(), cred, fp)
	if err != nil {
		httpError(w, statusFor(err), err.Error())
		return
	}
	s.log.Info("host created", "alias", h.Alias)
	writeJSON(w, http.StatusCreated, map[string]any{"host": viewHost(h), "sftpAvailable": sftpOK})
}

func (s *Server) handleUpdateHost(w http.ResponseWriter, r *http.Request, _ ownerCtx) {
	id := r.PathValue("id")
	var in hostInput
	if !readJSON(w, r, &in) {
		return
	}
	spec, err := store.ParseHostSpec(in.Alias, in.Name, in.Address, in.Username, in.Port)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	current, savedCred, err := s.store.HostSnapshot(r.Context(), id)
	if err != nil {
		httpError(w, statusFor(err), "host not found")
		return
	}
	u := store.HostUpdate{Spec: spec}
	cred := savedCred
	if in.Auth != nil {
		c, fp, err := parseCredential(*in.Auth)
		if err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		cred, u.Credential, u.KeyFingerprint = c, &c, fp
	}
	hostKey := current.HostKey
	if in.ObservationID != "" {
		key, ok := s.probes.get(in.ObservationID, spec.Endpoint())
		if !ok {
			httpError(w, http.StatusBadRequest, "host key observation expired or does not match this address and port")
			return
		}
		hostKey, u.HostKey = key.Marshal(), key.Marshal()
	} else if current.Endpoint() != spec.Endpoint() {
		httpError(w, http.StatusBadRequest, store.ErrTrustRequired.Error())
		return
	}
	sftpOK, err := testConnection(r.Context(), spec, hostKey, cred)
	if err != nil {
		connectionError(w, err)
		return
	}
	h, err := s.store.UpdateHost(r.Context(), id, in.Revision, u)
	if errors.Is(err, store.ErrConflict) {
		httpError(w, http.StatusConflict, "host was changed elsewhere; reload and retry")
		return
	}
	if err != nil {
		httpError(w, statusFor(err), err.Error())
		return
	}
	s.log.Info("host updated", "alias", h.Alias, "credential_replaced", u.Credential != nil, "host_key_replaced", u.HostKey != nil)
	writeJSON(w, http.StatusOK, map[string]any{"host": viewHost(h), "sftpAvailable": sftpOK})
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request, _ ownerCtx) {
	id := r.PathValue("id")
	if err := s.store.DeleteHost(r.Context(), id); err != nil {
		httpError(w, statusFor(err), "host not found")
		return
	}
	n := s.reg.RemoveHost(id)
	s.log.Info("host deleted", "id", id, "closed_sessions", n)
	w.WriteHeader(http.StatusNoContent)
}

// cliHost is the CLI's view: no credential or trust detail.
type cliHost struct {
	ID       string `json:"id"`
	Alias    string `json:"alias"`
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Username string `json:"username"`
}

func (s *Server) handleCLIHosts(w http.ResponseWriter, r *http.Request, _ deviceCtx) {
	hosts, err := s.store.ListHosts(r.Context())
	if err != nil {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]cliHost, len(hosts))
	for i, h := range hosts {
		out[i] = cliHost{ID: h.ID, Alias: h.Alias, Name: h.Name, Endpoint: net.JoinHostPort(h.Address, strconv.Itoa(h.Port)), Username: h.Username}
	}
	writeJSON(w, http.StatusOK, out)
}
