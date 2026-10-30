package discovery

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/s835773/OctoLAN/internal/capture"
	"github.com/s835773/OctoLAN/internal/netutil"
)

// ARPResult is a host that answered (or announced itself) on layer 2.
type ARPResult struct {
	IP  netip.Addr
	MAC net.HardwareAddr
}

// ARPSweep crafts raw ARP who-has frames for every target inside the
// interface's subnet (works even when hosts firewall ICMP and TCP) and
// reports replies. Requires a capture hub.
func ARPSweep(ctx context.Context, hub *capture.Hub, local netutil.LocalIface, targets []netip.Addr, rate int, wait time.Duration, onReply func(ARPResult)) error {
	srcMAC := local.Iface.HardwareAddr
	if len(srcMAC) != 6 {
		return errNoMAC
	}
	pkts, unsub := hub.Subscribe("arp-sweep", 8192)
	defer unsub()

	var mu sync.Mutex
	seen := map[netip.Addr]bool{}
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		for p := range pkts {
			ip, mac, ok := parseARPReply(p.Data)
			if !ok || !local.Prefix.Contains(ip) {
				continue
			}
			mu.Lock()
			first := !seen[ip]
			seen[ip] = true
			mu.Unlock()
			if first {
				onReply(ARPResult{IP: ip, MAC: mac})
			}
		}
	}()

	if rate <= 0 {
		rate = 400
	}
	pace := pacer(ctx, rate)
	for pass := 0; pass < 2 && ctx.Err() == nil; pass++ {
		for _, ip := range targets {
			if !local.Prefix.Contains(ip) || ip == local.Addr {
				continue
			}
			mu.Lock()
			skip := seen[ip]
			mu.Unlock()
			if skip {
				continue
			}
			if !pace() {
				break
			}
			_ = hub.Write(arpRequest(srcMAC, local.Addr, ip))
		}
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
	unsub()
	<-recvDone
	return ctx.Err()
}

type errString string

func (e errString) Error() string { return string(e) }

const errNoMAC = errString("interface has no Ethernet MAC address")

func arpRequest(srcMAC net.HardwareAddr, src, dst netip.Addr) []byte {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: src.AsSlice(),
		DstHwAddress:      make([]byte, 6),
		DstProtAddress:    dst.AsSlice(),
	}
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, &eth, &arp)
	return buf.Bytes()
}

// parseARPReply extracts sender IP/MAC from any ARP frame (replies, and
// requests/announcements, which also prove the sender is alive).
func parseARPReply(frame []byte) (netip.Addr, net.HardwareAddr, bool) {
	off := 12
	if len(frame) < 14 {
		return netip.Addr{}, nil, false
	}
	et := uint16(frame[off])<<8 | uint16(frame[off+1])
	if et == 0x8100 && len(frame) >= 18 {
		off += 4
		et = uint16(frame[off])<<8 | uint16(frame[off+1])
	}
	if et != 0x0806 {
		return netip.Addr{}, nil, false
	}
	a := frame[off+2:]
	if len(a) < 28 || a[4] != 6 || a[5] != 4 {
		return netip.Addr{}, nil, false
	}
	mac := net.HardwareAddr(append([]byte(nil), a[8:14]...))
	ip := netip.AddrFrom4([4]byte(a[14:18]))
	if ip.IsUnspecified() {
		return netip.Addr{}, nil, false
	}
	return ip, mac, true
}

// PrimeARP makes the OS resolve each local target by sending a single
// UDP datagram to the discard port. The kernel must ARP for the address
// first, which fills the OS ARP cache without needing raw sockets.
func PrimeARP(ctx context.Context, local netutil.LocalIface, targets []netip.Addr, rate int) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local.Addr.AsSlice()})
	if err != nil {
		return
	}
	defer conn.Close()
	pace := pacer(ctx, rate)
	for _, ip := range targets {
		if !local.Prefix.Contains(ip) || ip == local.Addr {
			continue
		}
		if !pace() {
			return
		}
		_, _ = conn.WriteToUDP([]byte{0}, &net.UDPAddr{IP: ip.AsSlice(), Port: 9})
	}
}

// WindowsARP resolves each local target with the SendARP API (Windows,
// no Npcap needed). On other OSes it does nothing.
func WindowsARP(ctx context.Context, local netutil.LocalIface, targets []netip.Addr, onReply func(ARPResult)) {
	work := make(chan netip.Addr)
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range work {
				if mac, err := netutil.SendARP(ip); err == nil {
					onReply(ARPResult{IP: ip, MAC: mac})
				}
			}
		}()
	}
	for _, ip := range targets {
		if !local.Prefix.Contains(ip) || ip == local.Addr {
			continue
		}
		select {
		case work <- ip:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(work)
	wg.Wait()
}
