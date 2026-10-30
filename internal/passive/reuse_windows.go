//go:build windows

package passive

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// reuseControl lets us share 5353/1900 with Windows' own responders.
func reuseControl(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return serr
}
