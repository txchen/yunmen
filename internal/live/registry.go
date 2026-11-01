// Package live tracks every running terminal and file transfer so that
// revocation, expiry, host removal and shutdown can end them.
//
// Registration and revocation serialize on one mutex, and revocations leave a
// tombstone. An open that authenticated just before a revocation committed
// therefore either fails to register or is ended by that revocation; it can
// never run untracked.
package live

import (
	"errors"
	"sync"
	"time"

	"github.com/txchen/yunmen/internal/protocol"
)

// Credential identifies the bearer credential behind an operation, e.g.
// "device:<id>" or "web:<id>".
type Credential string

func DeviceCredential(id string) Credential { return Credential("device:" + id) }
func WebCredential(id string) Credential    { return Credential("web:" + id) }

// EndFunc must be idempotent and must not block.
type EndFunc func(protocol.EndReason)

type Kind string

const (
	KindTerminal Kind = "terminal"
	KindTransfer Kind = "transfer"
)

type entry struct {
	cred   Credential
	hostID string
	keyID  string
	kind   Kind
	end    EndFunc
	timer  *time.Timer
}

type Registry struct {
	mu      sync.Mutex
	nextID  uint64
	entries map[uint64]*entry
	revoked map[Credential]struct{}
	removed map[string]struct{}
	// removedKeys tombstones deleted library keys.
	removedKeys map[string]struct{}
	shutdown    bool
	now         func() time.Time
}

func New() *Registry {
	return &Registry{entries: map[uint64]*entry{}, revoked: map[Credential]struct{}{}, removed: map[string]struct{}{}, removedKeys: map[string]struct{}{}, now: time.Now}
}

var (
	ErrRevoked     = errors.New("credential revoked")
	ErrExpired     = errors.New("credential expired")
	ErrHostRemoved = errors.New("host removed")
	ErrShutdown    = errors.New("server shutting down")
	ErrTooMany     = errors.New("too many open terminals and transfers for this credential")
	ErrKeyRemoved  = errors.New("the SSH key was removed from the key library")
)

// MaxPerCredential bounds concurrent operations for one credential, so a
// stolen token cannot open unbounded SSH connections.
const MaxPerCredential = 32

// Reason maps a registration error to the end reason shown to clients.
func Reason(err error) protocol.EndReason {
	switch {
	case errors.Is(err, ErrRevoked), errors.Is(err, ErrKeyRemoved):
		return protocol.EndRevoked
	case errors.Is(err, ErrExpired):
		return protocol.EndExpired
	case errors.Is(err, ErrHostRemoved):
		return protocol.EndHostRemoved
	case errors.Is(err, ErrShutdown):
		return protocol.EndServerShutdown
	}
	return protocol.EndOpenFailed
}

// Lease is one registered operation.
type Lease struct {
	r    *Registry
	id   uint64
	e    *entry
	once sync.Once
}

// Release stops tracking the operation. It is idempotent.
func (l *Lease) Release() {
	l.once.Do(func() {
		l.r.mu.Lock()
		delete(l.r.entries, l.id)
		l.r.mu.Unlock()
		l.e.timer.Stop()
	})
}

// BindKey records the library key the operation authenticates with, so
// removing that key ends it. It fails if the key was already removed.
func (l *Lease) BindKey(keyID string) error {
	l.r.mu.Lock()
	defer l.r.mu.Unlock()
	if _, gone := l.r.removedKeys[keyID]; gone {
		return ErrKeyRemoved
	}
	l.e.keyID = keyID
	return nil
}

// Register tracks an operation until Release is called. end is invoked when
// the deadline passes or the credential, host, key or server goes away.
// Call Register before allocating any SSH resources.
func (r *Registry) Register(cred Credential, hostID string, kind Kind, deadline time.Time, end EndFunc) (*Lease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.shutdown:
		return nil, ErrShutdown
	case r.isRevoked(cred):
		return nil, ErrRevoked
	case r.isRemoved(hostID):
		return nil, ErrHostRemoved
	}
	wait := deadline.Sub(r.now())
	if wait <= 0 {
		return nil, ErrExpired
	}
	n := 0
	for _, e := range r.entries {
		if e.cred == cred {
			n++
		}
	}
	if n >= MaxPerCredential {
		return nil, ErrTooMany
	}
	r.nextID++
	e := &entry{cred: cred, hostID: hostID, kind: kind, end: end}
	e.timer = time.AfterFunc(wait, func() { end(protocol.EndExpired) })
	r.entries[r.nextID] = e
	return &Lease{r: r, id: r.nextID, e: e}, nil
}

// RemoveKey ends every operation using keyID and rejects later binds.
func (r *Registry) RemoveKey(keyID string) int {
	r.mu.Lock()
	r.removedKeys[keyID] = struct{}{}
	return r.endMatching(func(e *entry) bool { return e.keyID == keyID }, protocol.EndRevoked)
}

func (r *Registry) isRevoked(c Credential) bool { _, ok := r.revoked[c]; return ok }
func (r *Registry) isRemoved(h string) bool     { _, ok := r.removed[h]; return ok }

func (r *Registry) endMatching(match func(*entry) bool, reason protocol.EndReason) int {
	var ends []EndFunc
	for _, e := range r.entries {
		if match(e) {
			ends = append(ends, e.end)
		}
	}
	r.mu.Unlock()
	for _, end := range ends {
		end(reason)
	}
	return len(ends)
}

// RevokeCredential must be called after the revocation is committed to the
// database. It ends every operation using cred and rejects future registrations.
func (r *Registry) RevokeCredential(cred Credential, reason protocol.EndReason) int {
	r.mu.Lock()
	r.revoked[cred] = struct{}{}
	return r.endMatching(func(e *entry) bool { return e.cred == cred }, reason)
}

// RemoveHost ends every operation on hostID and rejects future registrations.
func (r *Registry) RemoveHost(hostID string) int {
	r.mu.Lock()
	r.removed[hostID] = struct{}{}
	return r.endMatching(func(e *entry) bool { return e.hostID == hostID }, protocol.EndHostRemoved)
}

func (r *Registry) Shutdown() int {
	r.mu.Lock()
	r.shutdown = true
	return r.endMatching(func(*entry) bool { return true }, protocol.EndServerShutdown)
}

// Count reports live operations, optionally filtered by credential.
func (r *Registry) Count(cred Credential) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.entries {
		if cred == "" || e.cred == cred {
			n++
		}
	}
	return n
}

// Credentials lists the distinct credentials with live operations.
func (r *Registry) Credentials() []Credential {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := map[Credential]bool{}
	var out []Credential
	for _, e := range r.entries {
		if !seen[e.cred] {
			seen[e.cred] = true
			out = append(out, e.cred)
		}
	}
	return out
}

// Split returns the kind ("device" or "web") and ID of a credential.
func (c Credential) Split() (kind, id string) {
	s := string(c)
	for i := range s {
		if s[i] == ':' {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}
