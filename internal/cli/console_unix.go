//go:build !windows

package cli

import "os"

func openConsole() (*console, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &console{in: f, out: f}, nil
}

// prepareOutput is a no-op where terminals interpret escape sequences natively.
func prepareOutput(*os.File) (restore func()) { return func() {} }
