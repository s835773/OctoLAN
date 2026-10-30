// Package discovery contains OctoLAN's active probes: ICMP and ARP sweeps,
// TCP service scanning with SYN-ACK fingerprinting, SMB/NTLM and TLS
// inspection, name resolution and SNMP polling.
package discovery

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// PingResult is one echo reply.
type PingResult struct {
	IP  netip.Addr
	RTT time.Duration
	TTL int
}

// ErrNoICMP means neither raw nor datagram ICMP sockets are permitted.
var ErrNoICMP = errors.New("ICMP not permitted for this user")

// PingSweep sends echo requests to every target (two passes; the second
// only to hosts that stayed silent) at up to rate packets per second and
// calls onReply for each first reply. It returns the ICMP mode used.
func PingSweep(ctx context.Context, targets []netip.Addr, rate int, timeout time.Duration, onReply func(PingResult)) (string, error) {
	if rate <= 0 {
		rate = 400
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	return pingSweep(ctx, targets, rate, timeout, onReply)
}

// ICMPMode reports which ICMP mechanism is available without sending.
func ICMPMode() string { return icmpMode() }

func pacer(ctx context.Context, rate int) func() bool {
	interval := time.Second / time.Duration(rate)
	next := time.Now()
	return func() bool {
		next = next.Add(interval)
		if d := time.Until(next); d > 0 {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(d):
			}
		}
		return ctx.Err() == nil
	}
}
