//go:build !linux && !windows && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package capture

import "net"

func open(net.Interface, bool) (Handle, error) { return nil, ErrUnsupported }

func explain(err error) string { return err.Error() }
