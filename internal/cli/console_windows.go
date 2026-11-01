//go:build windows

package cli

import (
	"os"

	"golang.org/x/sys/windows"
)

func openConsole() (*console, error) {
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		in.Close()
		return nil, err
	}
	return &console{in: in, out: out}, nil
}

// prepareOutput makes the console interpret the remote's escape sequences
// itself and not insert carriage returns, so output bytes pass through as
// sent. It returns a func restoring the previous mode.
func prepareOutput(f *os.File) (restore func()) {
	h := windows.Handle(f.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return func() {}
	}
	vt := mode | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING | windows.ENABLE_PROCESSED_OUTPUT
	if windows.SetConsoleMode(h, vt|windows.DISABLE_NEWLINE_AUTO_RETURN) != nil {
		// Older consoles reject DISABLE_NEWLINE_AUTO_RETURN; VT matters more.
		windows.SetConsoleMode(h, vt)
	}
	return func() { windows.SetConsoleMode(h, mode) }
}
