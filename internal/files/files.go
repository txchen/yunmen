// Package files implements the minimal Web file operations over SFTP: list,
// download, and no-overwrite upload. Paths are data passed to SFTP, never to
// a shell. Each operation owns its own SSH connection.
package files

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pkg/sftp"
	"github.com/txchen/yunmen/internal/live"
	"github.com/txchen/yunmen/internal/protocol"
	"github.com/txchen/yunmen/internal/sshconn"
	"github.com/txchen/yunmen/internal/store"
	"golang.org/x/crypto/ssh"
)

const (
	MaxEntries  = 5000
	ChunkSize   = 8 << 20
	listTimeout = 30 * time.Second
	hardlinkExt = "hardlink@openssh.com"
)

// Error is a user-facing file error with an HTTP-ish category.
type Error struct {
	Kind Kind
	Msg  string
}

type Kind int

const (
	KindInvalid Kind = iota + 1
	KindNotFound
	KindConflict
	KindUnavailable // SFTP missing or unsafe semantics
	KindPermission
	KindTarget // connection-level failure
	KindGone   // upload unknown or ended
)

func (e *Error) Error() string { return e.Msg }

func fail(k Kind, msg string) error { return &Error{Kind: k, Msg: msg} }

type Service struct {
	store *store.Store
	reg   *live.Registry
	log   *slog.Logger

	mu      sync.Mutex
	uploads map[string]*upload

	// UploadIdle ends an upload when no chunk arrives for this long.
	UploadIdle time.Duration
}

func New(st *store.Store, reg *live.Registry, log *slog.Logger) *Service {
	return &Service{store: st, reg: reg, log: log, uploads: map[string]*upload{}, UploadIdle: 2 * time.Minute}
}

// Available reports whether the target offers the SFTP subsystem.
func Available(client *ssh.Client) bool {
	c, err := sftp.NewClient(client)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// Caller identifies who runs an operation, for revocation and expiry.
type Caller struct {
	Cred     live.Credential
	Deadline time.Time
}

// session is one registered SFTP connection.
type session struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	lease  *live.Lease
	ssh    *ssh.Client
	sftp   *sftp.Client
}

func (s *session) close() {
	s.cancel(nil)
	if s.sftp != nil {
		s.sftp.Close()
	}
	if s.ssh != nil {
		s.ssh.Close()
	}
	s.lease.Release()
}

var errEnded = errors.New("operation ended")

// open registers the operation before dialing so revocation always reaches it.
func (s *Service) open(parent context.Context, c Caller, hostID string) (*session, error) {
	ctx, cancel := context.WithCancelCause(parent)
	lease, err := s.reg.Register(c.Cred, hostID, live.KindTransfer, c.Deadline, func(r protocol.EndReason) {
		cancel(fail(KindGone, protocol.Describe(r)))
	})
	if err != nil {
		cancel(nil)
		return nil, fail(KindGone, protocol.Describe(live.Reason(err)))
	}
	sess := &session{ctx: ctx, cancel: cancel, lease: lease}
	host, cred, err := s.store.HostSnapshot(ctx, hostID)
	if err != nil {
		sess.close()
		return nil, fail(KindNotFound, "host not found")
	}
	if cred.KeyID != "" {
		if err := lease.BindKey(cred.KeyID); err != nil {
			sess.close()
			return nil, fail(KindGone, err.Error())
		}
	}
	sess.ssh, err = sshconn.Dial(ctx, host, cred)
	if err != nil {
		sess.close()
		if cause := context.Cause(ctx); cause != nil && cause != context.Canceled {
			return nil, cause
		}
		return nil, fail(KindTarget, err.Error())
	}
	sess.sftp, err = sftp.NewClient(sess.ssh)
	if err != nil {
		sess.close()
		return nil, fail(KindUnavailable, "SFTP is not available on this host; terminals still work")
	}
	// Closing the SSH client on cancel unblocks any in-flight SFTP request.
	context.AfterFunc(ctx, func() { sess.ssh.Close() })
	return sess, nil
}

func mapErr(sess *session, err error) error {
	if cause := context.Cause(sess.ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
	}
	var fe *Error
	switch {
	case errors.As(err, &fe):
		return fe
	case errors.Is(err, fs.ErrNotExist):
		return fail(KindNotFound, "no such file or directory")
	case errors.Is(err, fs.ErrPermission):
		return fail(KindPermission, "permission denied")
	}
	var se *sftp.StatusError
	if errors.As(err, &se) {
		return fail(KindTarget, "remote error: "+se.Error())
	}
	return fail(KindTarget, "remote operation failed")
}

func validPath(p string) bool { return !strings.ContainsRune(p, 0) && len(p) <= 4096 }

// ValidLeafName accepts a single path component for uploads.
func ValidLeafName(n string) bool {
	// 200 leaves room for the temporary-name suffix within NAME_MAX (255).
	return n != "" && n != "." && n != ".." && len(n) <= 200 && utf8.ValidString(n) && !strings.ContainsAny(n, "/\x00")
}

type EntryType string

const (
	TypeFile    EntryType = "file"
	TypeDir     EntryType = "dir"
	TypeSymlink EntryType = "symlink"
	TypeOther   EntryType = "other"
)

type Entry struct {
	Name    string    `json:"name"`
	Type    EntryType `json:"type"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"modTime"`
	// Target is the link target's type for symlinks, when it can be resolved.
	Target EntryType `json:"target,omitempty"`
	// ValidName is false for names that are not UTF-8; such entries are shown
	// but cannot be opened or downloaded.
	ValidName bool `json:"validName"`
}

type Listing struct {
	Path      string  `json:"path"`
	Entries   []Entry `json:"entries"`
	Truncated bool    `json:"truncated"`
}

func entryType(m fs.FileMode) EntryType {
	switch {
	case m.IsRegular():
		return TypeFile
	case m.IsDir():
		return TypeDir
	case m&fs.ModeSymlink != 0:
		return TypeSymlink
	}
	return TypeOther
}

// List returns a bounded listing. An empty dir means the account's home.
func (s *Service) List(ctx context.Context, c Caller, hostID, dir string) (Listing, error) {
	if !validPath(dir) {
		return Listing{}, fail(KindInvalid, "invalid path")
	}
	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	sess, err := s.open(ctx, c, hostID)
	if err != nil {
		return Listing{}, err
	}
	defer sess.close()
	if dir == "" {
		dir = "."
	}
	real, err := sess.sftp.RealPath(dir)
	if err != nil {
		return Listing{}, mapErr(sess, err)
	}
	infos, err := sess.sftp.ReadDirContext(sess.ctx, real)
	if err != nil {
		return Listing{}, mapErr(sess, err)
	}
	out := Listing{Path: real, Entries: make([]Entry, 0, min(len(infos), MaxEntries))}
	sort.Slice(infos, func(i, j int) bool {
		di, dj := infos[i].IsDir(), infos[j].IsDir()
		if di != dj {
			return di
		}
		return infos[i].Name() < infos[j].Name()
	})
	for _, fi := range infos {
		if len(out.Entries) == MaxEntries {
			out.Truncated = true
			break
		}
		e := Entry{Name: fi.Name(), Type: entryType(fi.Mode()), Size: fi.Size(), Mode: fi.Mode().String(), ModTime: fi.ModTime().UTC(), ValidName: utf8.ValidString(fi.Name())}
		if !e.ValidName {
			e.Name = strings.ToValidUTF8(fi.Name(), "\uFFFD")
		}
		if e.Type == TypeSymlink && e.ValidName {
			if t, err := sess.sftp.Stat(path.Join(real, fi.Name())); err == nil {
				e.Target = entryType(t.Mode())
			}
		}
		out.Entries = append(out.Entries, e)
	}
	return out, nil
}

// Download streams a regular file to w. onStart is called with the name and
// size before the first byte, so the caller can set headers.
func (s *Service) Download(ctx context.Context, c Caller, hostID, p string, onStart func(name string, size int64) io.Writer) error {
	if !validPath(p) || !path.IsAbs(p) {
		return fail(KindInvalid, "an absolute path is required")
	}
	sess, err := s.open(ctx, c, hostID)
	if err != nil {
		return err
	}
	defer sess.close()
	// Stat before Open: opening a FIFO or device could block the SFTP server.
	if fi, err := sess.sftp.Stat(p); err != nil {
		return mapErr(sess, err)
	} else if !fi.Mode().IsRegular() {
		return fail(KindInvalid, "only regular files can be downloaded")
	}
	f, err := sess.sftp.Open(p)
	if err != nil {
		return mapErr(sess, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return mapErr(sess, err)
	}
	if !fi.Mode().IsRegular() {
		return fail(KindInvalid, "only regular files can be downloaded")
	}
	w := onStart(path.Base(p), fi.Size())
	if _, err := f.WriteTo(w); err != nil {
		return mapErr(sess, err)
	}
	return nil
}

// Upload state machine: receiving -> committing -> complete, or -> closed on
// cancel, failure, idle timeout, revocation or shutdown. Every exit except
// complete removes the exact temporary file this upload created.
type uploadState int

const (
	stateReceiving uploadState = iota
	stateComplete
	stateClosed
)

type upload struct {
	id        string
	cred      live.Credential
	hostID    string
	finalPath string
	tempPath  string
	size      int64

	mu       sync.Mutex // serializes chunk, commit and cancel
	state    uploadState
	result   error // terminal result once closed or complete
	written  int64
	lastOff  int64
	lastLen  int64
	lastHash string
	sess     *session
	file     *sftp.File
	idle     *time.Timer
}

type UploadInfo struct {
	ID        string `json:"uploadId"`
	ChunkSize int    `json:"chunkSize"`
	Path      string `json:"path"`
}

// BeginUpload creates an exclusive temporary file next to the destination.
func (s *Service) BeginUpload(c Caller, hostID, dir, name string, size int64) (UploadInfo, error) {
	if !validPath(dir) || !path.IsAbs(dir) {
		return UploadInfo{}, fail(KindInvalid, "an absolute destination directory is required")
	}
	if !ValidLeafName(name) {
		return UploadInfo{}, fail(KindInvalid, "file name must be a single path component")
	}
	if size < 0 {
		return UploadInfo{}, fail(KindInvalid, "size must not be negative")
	}
	id := store.NewID()
	sess, err := s.open(context.Background(), c, hostID)
	if err != nil {
		return UploadInfo{}, err
	}
	if _, ok := sess.sftp.HasExtension(hardlinkExt); !ok {
		sess.close()
		return UploadInfo{}, fail(KindUnavailable, "this SFTP server cannot commit without overwriting (no "+hardlinkExt+"); upload refused")
	}
	u := &upload{id: id, cred: c.Cred, hostID: hostID, size: size, sess: sess,
		finalPath: path.Join(dir, name), tempPath: path.Join(dir, "."+name+".yunmen-"+id+".part")}
	if _, err := sess.sftp.Lstat(u.finalPath); err == nil {
		sess.close()
		return UploadInfo{}, fail(KindConflict, "a file named "+name+" already exists; choose another name")
	} else if !errors.Is(err, fs.ErrNotExist) {
		sess.close()
		return UploadInfo{}, mapErr(sess, err)
	}
	if err := s.store.RecordUpload(context.Background(), store.PendingUpload{ID: id, HostID: hostID, TempPath: u.tempPath}); err != nil {
		sess.close()
		return UploadInfo{}, fail(KindTarget, "could not record upload")
	}
	u.file, err = sess.sftp.OpenFile(u.tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		s.store.ForgetUpload(context.Background(), id)
		sess.close()
		return UploadInfo{}, mapErr(sess, err)
	}
	s.mu.Lock()
	s.uploads[id] = u
	s.mu.Unlock()
	u.idle = time.AfterFunc(s.UploadIdle, func() { s.abort(u, fail(KindGone, "upload timed out")) })
	context.AfterFunc(sess.ctx, func() { s.abort(u, context.Cause(sess.ctx)) })
	s.log.Info("upload started", "upload", id, "size", size)
	return UploadInfo{ID: id, ChunkSize: ChunkSize, Path: u.finalPath}, nil
}

func (s *Service) get(id string, cred live.Credential) (*upload, error) {
	s.mu.Lock()
	u := s.uploads[id]
	s.mu.Unlock()
	// An upload is bound to the browser session that began it.
	if u == nil || u.cred != cred {
		return nil, fail(KindGone, "upload not found or already finished")
	}
	return u, nil
}

// abort ends a receiving upload and removes its temporary file.
func (s *Service) abort(u *upload, cause error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	s.closeLocked(u, cause)
}

func (s *Service) closeLocked(u *upload, cause error) {
	if u.state != stateReceiving {
		return
	}
	if cause == nil {
		cause = fail(KindGone, "upload cancelled")
	}
	u.state, u.result = stateClosed, cause
	u.idle.Stop()
	u.file.Close()
	removeErr := u.sess.sftp.Remove(u.tempPath)
	u.sess.close()
	if removeErr == nil || errors.Is(removeErr, fs.ErrNotExist) {
		s.store.ForgetUpload(context.Background(), u.id)
	} else {
		// The session was likely cancelled (revocation, shutdown). Cleanup is
		// housekeeping, so it uses its own connection outside the registry.
		go s.cleanupOne(context.Background(), store.PendingUpload{ID: u.id, HostID: u.hostID, TempPath: u.tempPath})
	}
	s.forgetLater(u)
	s.log.Info("upload closed", "upload", u.id, "reason", cause.Error())
}

// forgetLater keeps the final result briefly so a retried commit or chunk
// learns the outcome instead of "not found".
func (s *Service) forgetLater(u *upload) {
	time.AfterFunc(10*time.Minute, func() {
		s.mu.Lock()
		delete(s.uploads, u.id)
		s.mu.Unlock()
	})
}

// WriteChunk appends body at offset. A retry of the last accepted chunk with
// the same offset, length and digest is acknowledged without rewriting.
func (s *Service) WriteChunk(id string, cred live.Credential, offset int64, sha256hex string, body io.Reader) (int64, error) {
	u, err := s.get(id, cred)
	if err != nil {
		return 0, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.state != stateReceiving {
		return u.written, u.result
	}
	// The idle timer measures time between chunks, not the duration of one.
	u.idle.Stop()
	defer func() {
		if u.state == stateReceiving {
			u.idle.Reset(s.UploadIdle)
		}
	}()
	if offset == u.lastOff && offset+u.lastLen == u.written && sha256hex == u.lastHash && u.lastLen > 0 {
		io.Copy(io.Discard, io.LimitReader(body, ChunkSize+1))
		return u.written, nil
	}
	if offset != u.written {
		return u.written, fail(KindConflict, "unexpected chunk offset")
	}
	h := sha256.New()
	src := &readErr{r: io.LimitReader(body, min(ChunkSize, u.size-u.written)+1)}
	n, err := io.Copy(io.MultiWriter(u.file, h), src)
	rollback := func(msg string) (int64, error) {
		if err := u.file.Truncate(offset); err != nil {
			s.closeLocked(u, mapErr(u.sess, err))
			return u.written, u.result
		}
		if _, err := u.file.Seek(offset, io.SeekStart); err != nil {
			s.closeLocked(u, mapErr(u.sess, err))
			return u.written, u.result
		}
		return u.written, fail(KindInvalid, msg)
	}
	switch {
	case src.err != nil:
		return rollback("chunk upload interrupted; resend it")
	case err != nil:
		s.closeLocked(u, mapErr(u.sess, err))
		return u.written, u.result
	case n > ChunkSize || u.written+n > u.size:
		s.closeLocked(u, fail(KindInvalid, "chunk exceeds the declared size"))
		return u.written, u.result
	case hex.EncodeToString(h.Sum(nil)) != sha256hex:
		return rollback("chunk digest mismatch; resend it")
	}
	u.written += n
	u.lastOff, u.lastLen, u.lastHash = offset, n, sha256hex
	return u.written, nil
}

// Commit publishes the temporary file under its final name without ever
// replacing an existing entry: hardlink(2) fails if the name exists.
func (s *Service) Commit(id string, cred live.Credential) (string, error) {
	u, err := s.get(id, cred)
	if err != nil {
		return "", err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	switch u.state {
	case stateComplete:
		return u.finalPath, nil
	case stateClosed:
		return "", u.result
	}
	if u.written != u.size {
		return "", fail(KindInvalid, "upload incomplete")
	}
	if err := u.file.Close(); err != nil {
		s.closeLocked(u, mapErr(u.sess, err))
		return "", u.result
	}
	if err := u.sess.sftp.Link(u.tempPath, u.finalPath); err != nil {
		if _, statErr := u.sess.sftp.Lstat(u.finalPath); statErr == nil {
			s.closeLocked(u, fail(KindConflict, "a file named "+path.Base(u.finalPath)+" already exists; nothing was overwritten"))
		} else {
			s.closeLocked(u, mapErr(u.sess, err))
		}
		return "", u.result
	}
	if err := u.sess.sftp.Remove(u.tempPath); err != nil {
		s.log.Warn("committed upload but could not remove temporary link", "upload", u.id)
	} else {
		s.store.ForgetUpload(context.Background(), u.id)
	}
	u.state = stateComplete
	u.idle.Stop()
	u.sess.close()
	s.forgetLater(u)
	s.log.Info("upload committed", "upload", u.id, "bytes", u.written)
	return u.finalPath, nil
}

func (s *Service) Cancel(id string, cred live.Credential) error {
	u, err := s.get(id, cred)
	if err != nil {
		return err
	}
	s.abort(u, fail(KindGone, "upload cancelled"))
	return nil
}

// CleanupPending removes temporary files left by uploads interrupted by a
// restart. It deletes only the exact recorded paths.
func (s *Service) CleanupPending(ctx context.Context) {
	pending, err := s.store.PendingUploads(ctx)
	if err != nil || len(pending) == 0 {
		return
	}
	for _, p := range pending {
		s.cleanupOne(ctx, p)
	}
}

func (s *Service) cleanupOne(ctx context.Context, p store.PendingUpload) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	host, cred, err := s.store.HostSnapshot(ctx, p.HostID)
	if errors.Is(err, store.ErrNotFound) {
		s.store.ForgetUpload(ctx, p.ID)
		return
	}
	if err != nil {
		return
	}
	client, err := sshconn.Dial(ctx, host, cred)
	if err != nil {
		return
	}
	defer client.Close()
	sc, err := sftp.NewClient(client)
	if err != nil {
		return
	}
	defer sc.Close()
	if err := sc.Remove(p.TempPath); err == nil || errors.Is(err, fs.ErrNotExist) {
		s.store.ForgetUpload(ctx, p.ID)
		s.log.Info("removed interrupted upload", "upload", p.ID)
	}
}

// readErr records a failure reading the request body, as distinct from a
// failure writing to the target.
type readErr struct {
	r   io.Reader
	err error
}

func (r *readErr) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err != nil && err != io.EOF {
		r.err = err
	}
	return n, err
}
