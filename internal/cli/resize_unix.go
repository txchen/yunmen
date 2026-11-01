//go:build unix

package cli

import (
	"os"
	"os/signal"
	"syscall"
)

func watchResize() (<-chan struct{}, func()) {
	sig := make(chan os.Signal, 1)
	out := make(chan struct{}, 1)
	signal.Notify(sig, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-sig:
				select {
				case out <- struct{}{}:
				default:
				}
			case <-done:
				return
			}
		}
	}()
	return out, func() { signal.Stop(sig); close(done) }
}
