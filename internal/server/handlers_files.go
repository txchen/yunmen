package server

import (
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/txchen/yunmen/internal/files"
)

func (o ownerCtx) caller() files.Caller { return files.Caller{Cred: o.cred, Deadline: o.deadline} }

func filesError(w http.ResponseWriter, err error) {
	var fe *files.Error
	if !errors.As(err, &fe) {
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	status := map[files.Kind]int{
		files.KindInvalid:     http.StatusBadRequest,
		files.KindNotFound:    http.StatusNotFound,
		files.KindConflict:    http.StatusConflict,
		files.KindUnavailable: http.StatusNotImplemented,
		files.KindPermission:  http.StatusForbidden,
		files.KindTarget:      http.StatusBadGateway,
		files.KindGone:        http.StatusGone,
	}[fe.Kind]
	writeJSON(w, status, map[string]string{"error": fe.Msg})
}

func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request, o ownerCtx) {
	l, err := s.files.List(r.Context(), o.caller(), r.PathValue("id"), r.URL.Query().Get("path"))
	if err != nil {
		filesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request, o ownerCtx) {
	started := false
	err := s.files.Download(r.Context(), o.caller(), r.PathValue("id"), r.URL.Query().Get("path"), func(name string, size int64) io.Writer {
		started = true
		h := w.Header()
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
		h.Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		return w
	})
	if err != nil && !started {
		filesError(w, err)
	}
	// After headers are sent a failure truncates the body; Content-Length
	// makes the browser report the download as failed, never complete.
}

func (s *Server) handleBeginUpload(w http.ResponseWriter, r *http.Request, o ownerCtx) {
	var req struct {
		Directory string `json:"directory"`
		Name      string `json:"name"`
		Size      int64  `json:"size"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	info, err := s.files.BeginUpload(o.caller(), r.PathValue("id"), req.Directory, req.Name, req.Size)
	if err != nil {
		filesError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

func (s *Server) handleUploadChunk(w http.ResponseWriter, r *http.Request, o ownerCtx) {
	offset, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	digest := strings.ToLower(r.Header.Get("X-Content-SHA256"))
	if err != nil || offset < 0 || len(digest) != 64 {
		httpError(w, http.StatusBadRequest, "offset query parameter and X-Content-SHA256 header are required")
		return
	}
	confirmed, err := s.files.WriteChunk(r.PathValue("id"), o.cred, offset, digest, http.MaxBytesReader(w, r.Body, files.ChunkSize+1))
	if err != nil {
		var fe *files.Error
		if errors.As(err, &fe) && fe.Kind == files.KindConflict {
			writeJSON(w, http.StatusConflict, map[string]any{"error": fe.Msg, "confirmed": confirmed})
			return
		}
		filesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"confirmed": confirmed})
}

func (s *Server) handleCommitUpload(w http.ResponseWriter, r *http.Request, o ownerCtx) {
	p, err := s.files.Commit(r.PathValue("id"), o.cred)
	if err != nil {
		filesError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"path": p})
}

func (s *Server) handleCancelUpload(w http.ResponseWriter, r *http.Request, o ownerCtx) {
	if err := s.files.Cancel(r.PathValue("id"), o.cred); err != nil {
		filesError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleStatic serves the embedded Vue build with an index.html fallback for
// client-side routes.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request, _ accessIdentity) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name != "" && name != "index.html" {
		if f, err := fs.Stat(s.web, name); err == nil && !f.IsDir() {
			if strings.HasPrefix(name, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.ServeFileFS(w, r, s.web, name)
			return
		}
		if strings.HasPrefix(name, "assets/") {
			http.NotFound(w, r)
			return
		}
	}
	index, err := fs.ReadFile(s.web, "index.html")
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("Yunmen web UI is not built into this binary. Run `make web` and rebuild.\n"))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(index)
}
