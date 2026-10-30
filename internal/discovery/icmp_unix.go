//go:build !windows

package discovery

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var pingMagic = []byte("OctoLAN-ping")

func listenICMP() (*icmp.PacketConn, string, error) {
	if c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
		return c, "raw", nil
	}
	if c, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
		return c, "datagram", nil
	}
	return nil, "tcp-only", ErrNoICMP
}

func icmpMode() string {
	c, mode, err := listenICMP()
	if err == nil {
		c.Close()
	}
	return mode
}

func pingSweep(ctx context.Context, targets []netip.Addr, rate int, timeout time.Duration, onReply func(PingResult)) (string, error) {
	conn, mode, err := listenICMP()
	if err != nil {
		return mode, err
	}
	defer conn.Close()
	pc := conn.IPv4PacketConn()
	_ = pc.SetControlMessage(ipv4.FlagTTL, true)

	var mu sync.Mutex
	seen := make(map[netip.Addr]bool, len(targets))
	start := time.Now()
	id := os.Getpid() & 0xffff

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, cm, src, err := pc.ReadFrom(buf)
			now := time.Now()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					if ctx.Err() != nil {
						return
					}
					select {
					case <-done:
						return
					default:
					}
					continue
				}
				return
			}
			payload, ttl := buf[:n], 0
			if cm != nil {
				ttl = cm.TTL
			}
			// macOS datagram sockets hand us the IP header too.
			if len(payload) >= 20 && payload[0]>>4 == 4 {
				ihl := int(payload[0]&0x0f) * 4
				if ihl >= 20 && len(payload) > ihl && payload[9] == 1 {
					ttl = int(payload[8])
					payload = payload[ihl:]
				}
			}
			msg, err := icmp.ParseMessage(1, payload)
			if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			echo, ok := msg.Body.(*icmp.Echo)
			if !ok || len(echo.Data) < 8+len(pingMagic) || !bytes.Equal(echo.Data[8:8+len(pingMagic)], pingMagic) {
				continue
			}
			sent := time.Duration(binary.BigEndian.Uint64(echo.Data[:8]))
			rtt := now.Sub(start) - sent
			var ip netip.Addr
			switch a := src.(type) {
			case *net.IPAddr:
				ip, _ = netip.AddrFromSlice(a.IP)
			case *net.UDPAddr:
				ip, _ = netip.AddrFromSlice(a.IP)
			}
			ip = ip.Unmap()
			mu.Lock()
			first := !seen[ip]
			seen[ip] = true
			mu.Unlock()
			if first && ip.IsValid() {
				onReply(PingResult{IP: ip, RTT: rtt, TTL: ttl})
			}
		}
	}()

	send := func(seq int, ip netip.Addr) {
		data := make([]byte, 8, 8+len(pingMagic)+16)
		binary.BigEndian.PutUint64(data, uint64(time.Since(start)))
		data = append(data, pingMagic...)
		data = append(data, make([]byte, 16)...)
		m := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq & 0xffff, Data: data}}
		b, err := m.Marshal(nil)
		if err != nil {
			return
		}
		var dst net.Addr = &net.IPAddr{IP: ip.AsSlice()}
		if mode == "datagram" {
			dst = &net.UDPAddr{IP: ip.AsSlice()}
		}
		_, _ = conn.WriteTo(b, dst)
	}

	wait := pacer(ctx, rate)
	for pass := 0; pass < 2 && ctx.Err() == nil; pass++ {
		for i, ip := range targets {
			mu.Lock()
			skip := seen[ip]
			mu.Unlock()
			if skip {
				continue
			}
			if !wait() {
				break
			}
			send(i+pass*len(targets), ip)
		}
		select {
		case <-ctx.Done():
		case <-time.After(timeout):
		}
	}
	conn.Close()
	<-done
	return mode, ctx.Err()
}
