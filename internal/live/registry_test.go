package live

import (
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/txchen/yunmen/internal/protocol"
)

// Generated interleavings: for each seed, many registrations race one
// revocation. Afterwards every registration either failed or was ended with
// "revoked", and nothing for the credential stays registered.
func TestRevokeRacingRegisterNeverLeavesUntrackedSessions(t *testing.T) {
	for seed := uint64(0); seed < 200; seed++ {
		rng := rand.New(rand.NewPCG(seed, 99))
		r := New()
		cred := DeviceCredential("d")
		other := DeviceCredential("o")
		n := 2 + rng.IntN(30)
		revokeAt := rng.IntN(n)
		var wg sync.WaitGroup
		var ended, unended atomic.Int64
		var survivors sync.Map
		for i := range n {
			if i == revokeAt {
				wg.Add(1)
				go func() { defer wg.Done(); r.RevokeCredential(cred, protocol.EndRevoked) }()
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := cred
				if i%5 == 4 {
					c = other
				}
				var gotEnd atomic.Bool
				_, err := r.Register(c, "h", KindTerminal, time.Now().Add(time.Hour), func(reason protocol.EndReason) {
					if reason == protocol.EndRevoked {
						gotEnd.Store(true)
						ended.Add(1)
					}
				})
				if err == nil && c == cred {
					survivors.Store(i, &gotEnd)
				}
				if err == nil && c == other {
					unended.Add(1)
				}
			}()
		}
		wg.Wait()
		survivors.Range(func(_, v any) bool {
			if !v.(*atomic.Bool).Load() {
				t.Fatalf("seed %d: a session registered for a revoked credential was never ended", seed)
			}
			return true
		})
		if _, err := r.Register(cred, "h", KindTerminal, time.Now().Add(time.Hour), func(protocol.EndReason) {}); err != ErrRevoked {
			t.Fatalf("seed %d: registration after revoke: %v", seed, err)
		}
		if r.Count(other) != int(unended.Load()) {
			t.Fatalf("seed %d: revocation affected another credential", seed)
		}
	}
}

func TestDeadlineEndsRegistration(t *testing.T) {
	r := New()
	got := make(chan protocol.EndReason, 1)
	lease, err := r.Register(WebCredential("w"), "h", KindTerminal, time.Now().Add(50*time.Millisecond), func(e protocol.EndReason) { got <- e })
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	select {
	case e := <-got:
		if e != protocol.EndExpired {
			t.Fatalf("reason %s", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("deadline did not end the session")
	}
	if _, err := r.Register(WebCredential("w"), "h", KindTerminal, time.Now().Add(-time.Second), nil); err != ErrExpired {
		t.Fatalf("expired deadline accepted: %v", err)
	}
}
