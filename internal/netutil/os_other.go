//go:build !linux && !windows

package netutil

import (
	"errors"
	"net"
	"net/netip"
)

func linuxGateway() (netip.Addr, error) { return netip.Addr{}, ErrNoGateway }
func linuxARP() ([]ARPEntry, error)     { return nil, nil }
func windowsARP() ([]ARPEntry, error)   { return nil, nil }

// SendARP is only implemented on Windows.
func SendARP(netip.Addr) (net.HardwareAddr, error) { return nil, errors.New("unsupported") }
