package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
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
	KeyID      string         `json:"keyId"`
	PrivateKey string         `json:"privateKey"`
	Passphrase string         `json:"passphrase"`
	KeyLabel   string         `json:"keyLabel"`
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

// pendingAuth is a parsed auth input. A key imported inline is added to
// the library only after the connection test passes, so a failed save
// leaves nothing behind.
type pendingAuth struct {
	auth     store.HostAuth
	cred     store.Credential
	newKey   *store.KeyMaterial
	keyLabel string
}

func (s *Server) parseAuth(ctx context.Context, a authInput, alias string) (pendingAuth, int, error) {
	switch a.Kind {
	case store.AuthKey:
		if a.KeyID != "" {
			cred, err := s.store.KeyCredential(ctx, a.KeyID)
			if err != nil {
				return pendingAuth{}, http.StatusBadRequest, store.ErrNoSuchKey
			}
			return pendingAuth{auth: store.HostAuth{Kind: store.AuthKey, KeyID: a.KeyID}, cred: cred}, 0, nil
		}
		m, err := sshconn.ImportPrivateKey([]byte(a.PrivateKey), a.Passphrase)
		if err != nil {
			return pendingAuth{}, http.StatusBadRequest, err
		}
		label := a.KeyLabel
		if strings.TrimSpace(label) == "" {
			label = alias + " key"
		}
		if label, err = store.ParseKeyLabel(label); err != nil {
			return pendingAuth{}, http.StatusBadRequest, err
		}
		return pendingAuth{auth: store.HostAuth{Kind: store.AuthKey}, cred: store.Credential{Kind: store.AuthKey, PrivateKey: m.PEM},
			newKey: &m, keyLabel: label}, 0, nil
	case store.AuthPassword:
		if a.Password == "" || len(a.Password) > 1024 {
			return pendingAuth{}, http.StatusBadRequest, errors.New("password must be 1-1024 bytes")
		}
		return pendingAuth{auth: store.HostAuth{Kind: store.AuthPassword, Password: a.Password},
			cred: store.Credential{Kind: store.AuthPassword, Password: a.Password}}, 0, nil
	}
	return pendingAuth{}, http.StatusBadRequest, errors.New("auth.kind must be `key` or `password`")
}

// commitKey stores an inline-imported key, reusing a library entry with
// the same fingerprint (whose label is kept). It returns an undo func that
// removes a key it created, for when the host write then fails.
func (s *Server) commitKey(ctx context.Context, p *pendingAuth) (undo func(), err error) {
	undo = func() {}
	if p.newKey == nil {
		return undo, nil
	}
	if k, err := s.store.KeyByFingerprint(ctx, p.newKey.Fingerprint); err == nil {
		p.auth.KeyID = k.ID
		return undo, nil
	}
	k, err := s.store.CreateKey(ctx, p.keyLabel, *p.newKey)
	if errors.Is(err, store.ErrKeyExists) {
		if k, err = s.store.KeyByFingerprint(ctx, p.newKey.Fingerprint); err == nil {
			p.auth.KeyID = k.ID
		}
		return undo, err
	}
	if err != nil {
		return undo, err
	}
	p.auth.KeyID = k.ID
	return func() { s.store.DeleteKey(context.WithoutCancel(ctx), k.ID) }, nil
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
	pa, status, err := s.parseAuth(r.Context(), *in.Auth, spec.Alias)
	if err != nil {
		httpError(w, status, err.Error())
		return
	}
	key, ok := s.probes.get(in.ObservationID, spec.Endpoint())
	if !ok {
		httpError(w, http.StatusBadRequest, "verify the host key first (probe expired or does not match this address and port)")
		return
	}
	sftpOK, err := testConnection(r.Context(), spec, key.Marshal(), pa.cred)
	if err != nil {
		connectionError(w, err)
		return
	}
	undoKey, err := s.commitKey(r.Context(), &pa)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "could not store the key")
		return
	}
	h, err := s.store.CreateHost(r.Context(), spec, key.Marshal(), pa.auth)
	if err != nil {
		undoKey()
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
	var pa pendingAuth
	if in.Auth != nil {
		var status int
		if pa, status, err = s.parseAuth(r.Context(), *in.Auth, spec.Alias); err != nil {
			httpError(w, status, err.Error())
			return
		}
		cred = pa.cred
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
	undoKey := func() {}
	if in.Auth != nil {
		if undoKey, err = s.commitKey(r.Context(), &pa); err != nil {
			httpError(w, http.StatusInternalServerError, "could not store the key")
			return
		}
		u.Auth = &pa.auth
	}
	h, err := s.store.UpdateHost(r.Context(), id, in.Revision, u)
	if err != nil {
		undoKey()
	}
	if errors.Is(err, store.ErrConflict) {
		httpError(w, http.StatusConflict, "host was changed elsewhere; reload and retry")
		return
	}
	if err != nil {
		httpError(w, statusFor(err), err.Error())
		return
	}
	s.log.Info("host updated", "alias", h.Alias, "credential_replaced", u.Auth != nil, "host_key_replaced", u.HostKey != nil)
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
