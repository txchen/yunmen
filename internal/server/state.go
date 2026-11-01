package server

import (
	"crypto/rand"
	"crypto/subtle"
	"strings"
	"sync"
	"time"

	"github.com/txchen/yunmen/internal/store"
	"golang.org/x/crypto/ssh"
)

// limiter bounds failed owner-credential checks per key within a window.
// Attempts are reserved before the slow password hash runs, so parallel
// requests cannot all pass the check before any failure is recorded.
type limiter struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	failures map[string][]time.Time
	inflight map[string]int
	now      func() time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, failures: map[string][]time.Time{}, inflight: map[string]int{}, now: time.Now}
}

func (l *limiter) recent(key string) int {
	cut := l.now().Add(-l.window)
	f := l.failures[key]
	i := 0
	for i < len(f) && f[i].Before(cut) {
		i++
	}
	if f = f[i:]; len(f) == 0 {
		delete(l.failures, key)
	} else {
		l.failures[key] = f
	}
	return len(f)
}

// reserve returns a completion func, or false when key is over budget.
func (l *limiter) reserve(key string) (func(failed bool), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.recent(key)+l.inflight[key] >= l.max {
		return nil, false
	}
	l.inflight[key]++
	return func(failed bool) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.inflight[key]--; l.inflight[key] == 0 {
			delete(l.inflight, key)
		}
		if failed {
			l.failures[key] = append(l.failures[key], l.now())
		}
	}, true
}

// Pairing lifecycle: Pending -> Approved -> (consumed by poll) | Denied | expired.
type pairState string

const (
	pairPending  pairState = "pending"
	pairApproved pairState = "approved"
	pairDenied   pairState = "denied"
)

const (
	pairTTL          = 5 * time.Minute
	pairPollInterval = 2 * time.Second
	maxPendingPairs  = 10
)

type pairing struct {
	userCode  string
	pollHash  []byte
	label     string
	principal string
	created   time.Time
	expires   time.Time
	lastPoll  time.Time
	state     pairState
}

type pairings struct {
	mu     sync.Mutex
	byCode map[string]*pairing
	now    func() time.Time
}

func newPairings() *pairings { return &pairings{byCode: map[string]*pairing{}, now: time.Now} }

// Unambiguous uppercase alphabet for codes read off a terminal.
const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func newUserCode() string {
	b := make([]byte, 8)
	rand.Read(b)
	for i := range b {
		b[i] = codeAlphabet[int(b[i])%len(codeAlphabet)]
	}
	return string(b[:4]) + "-" + string(b[4:])
}

func normalizeCode(c string) string {
	c = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(c), "-", ""))
	if len(c) != 8 {
		return ""
	}
	return c[:4] + "-" + c[4:]
}

func (p *pairings) gc() {
	now := p.now()
	for k, v := range p.byCode {
		if now.After(v.expires) {
			delete(p.byCode, k)
		}
	}
}

func (p *pairings) start(label, principal string) (pollToken string, pr pairing, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gc()
	if len(p.byCode) >= maxPendingPairs {
		return "", pairing{}, false
	}
	raw, hash := store.NewToken("ymp_")
	now := p.now()
	n := &pairing{userCode: newUserCode(), pollHash: hash, label: label, principal: principal, created: now, expires: now.Add(pairTTL), state: pairPending}
	for p.byCode[n.userCode] != nil {
		n.userCode = newUserCode()
	}
	p.byCode[n.userCode] = n
	return raw, *n, true
}

// lookup returns a pending pairing by user code.
func (p *pairings) lookup(code string) (pairing, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gc()
	n, ok := p.byCode[normalizeCode(code)]
	if !ok || n.state != pairPending {
		return pairing{}, false
	}
	return *n, true
}

func (p *pairings) decide(code string, approve bool) (pairing, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gc()
	n, ok := p.byCode[normalizeCode(code)]
	if !ok || n.state != pairPending {
		return pairing{}, false
	}
	if approve {
		n.state = pairApproved
	} else {
		n.state = pairDenied
	}
	return *n, true
}

type pollResult string

const (
	pollPending  pollResult = "pending"
	pollSlowDown pollResult = "slow_down"
	pollApproved pollResult = "approved"
	pollDenied   pollResult = "denied"
	pollExpired  pollResult = "expired"
)

// poll consumes an approved or denied pairing. The poll token and the
// service principal that started the pairing must both match.
func (p *pairings) poll(pollToken, principal string) (pollResult, pairing) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gc()
	hash := store.HashToken(pollToken)
	for code, n := range p.byCode {
		if subtle.ConstantTimeCompare(n.pollHash, hash) != 1 {
			continue
		}
		if n.principal != principal {
			return pollExpired, pairing{}
		}
		now := p.now()
		if now.Sub(n.lastPoll) < pairPollInterval {
			n.lastPoll = now
			return pollSlowDown, pairing{}
		}
		n.lastPoll = now
		switch n.state {
		case pairApproved:
			delete(p.byCode, code)
			return pollApproved, *n
		case pairDenied:
			delete(p.byCode, code)
			return pollDenied, pairing{}
		}
		return pollPending, pairing{}
	}
	return pollExpired, pairing{}
}

// Host key observations: a probe result the owner must explicitly approve.
const observationTTL = 10 * time.Minute

type observation struct {
	endpoint string
	key      ssh.PublicKey
	expires  time.Time
}

type observations struct {
	mu   sync.Mutex
	byID map[string]observation
	now  func() time.Time
}

func newObservations() *observations {
	return &observations{byID: map[string]observation{}, now: time.Now}
}

func (o *observations) add(endpoint string, key ssh.PublicKey) (string, time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	for id, v := range o.byID {
		if now.After(v.expires) {
			delete(o.byID, id)
		}
	}
	id := store.NewID()
	exp := now.Add(observationTTL)
	o.byID[id] = observation{endpoint: endpoint, key: key, expires: exp}
	return id, exp
}

// get returns the observed key if id is valid for endpoint. It does not
// consume the observation, so a failed credential test can be retried.
func (o *observations) get(id, endpoint string) (ssh.PublicKey, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	v, ok := o.byID[id]
	if !ok || o.now().After(v.expires) || v.endpoint != endpoint {
		return nil, false
	}
	return v.key, true
}
