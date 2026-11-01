//go:build !unix

package cli

import "time"

// Without SIGWINCH, poll; RunTerminal only sends a resize when the size changes.
func watchResize() (<-chan struct{}, func()) {
	out := make(chan struct{}, 1)
	t := time.NewTicker(250 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-t.C:
				select {
				case out <- struct{}{}:
				default:
				}
			case <-done:
				return
			}
		}
	}()
	return out, func() { t.Stop(); close(done) }
}
