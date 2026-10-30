package discovery

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ReverseDNS looks up PTR names for ip.
func ReverseDNS(ctx context.Context, ip netip.Addr, timeout time.Duration) []string {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
	if err != nil {
		return nil
	}
	for i := range names {
		names[i] = strings.TrimSuffix(names[i], ".")
	}
	return names
}

// NetBIOSInfo is the result of a node status (NBSTAT) query.
type NetBIOSInfo struct {
	Name      string
	Workgroup string
	MAC       net.HardwareAddr
	User      string
	IsDC      bool
	IsFile    bool
}

// NetBIOSStatus sends an NBSTAT "*" query to UDP 137.
func NetBIOSStatus(ctx context.Context, ip netip.Addr, timeout time.Duration) *NetBIOSInfo {
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	q := make([]byte, 12, 50)
	binary.BigEndian.PutUint16(q[0:], uint16(rand.IntN(0xffff)))
	binary.BigEndian.PutUint16(q[4:], 1) // QDCOUNT
	q = append(q, 0x20)
	// "*" padded with NULs, first-level encoded.
	name := [16]byte{'*'}
	for _, b := range name {
		q = append(q, 'A'+b>>4, 'A'+b&0x0f)
	}
	q = append(q, 0, 0x00, 0x21, 0x00, 0x01) // NBSTAT, IN
	if _, err := c.WriteToUDP(q, &net.UDPAddr{IP: ip.AsSlice(), Port: 137}); err != nil {
		return nil
	}
	buf := make([]byte, 2048)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil || n < 57 {
		return nil
	}
	b := buf[:n]
	// Skip header (12) + name (34) + type/class/ttl (8) + rdlength (2).
	off := 12 + 34 + 10
	if off >= len(b) {
		return nil
	}
	count := int(b[off])
	off++
	info := &NetBIOSInfo{}
	for i := 0; i < count && off+18 <= len(b); i++ {
		raw := b[off : off+15]
		suffix := b[off+15]
		flags := binary.BigEndian.Uint16(b[off+16 : off+18])
		off += 18
		nm := strings.TrimRight(string(raw), " \x00")
		group := flags&0x8000 != 0
		switch {
		case suffix == 0x00 && !group && info.Name == "":
			info.Name = nm
		case suffix == 0x00 && group && info.Workgroup == "":
			info.Workgroup = nm
		case suffix == 0x1c && group:
			info.IsDC = true
		case suffix == 0x20:
			info.IsFile = true
		case suffix == 0x03 && !group && nm != info.Name && info.User == "":
			info.User = nm
		}
	}
	if off+6 <= len(b) {
		mac := net.HardwareAddr(append([]byte(nil), b[off:off+6]...))
		if mac.String() != "00:00:00:00:00:00" {
			info.MAC = mac
		}
	}
	if info.Name == "" {
		return nil
	}
	return info
}

// MDNSReverse asks the host itself (unicast to port 5353) for its .local
// name. Apple devices, Linux with Avahi, printers and many IoT devices
// answer.
func MDNSReverse(ctx context.Context, ip netip.Addr, timeout time.Duration) string {
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return ""
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	a := ip.As4()
	rev := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", a[3], a[2], a[1], a[0])
	name, err := dnsmessage.NewName(rev)
	if err != nil {
		return ""
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: uint16(rand.IntN(0xffff))},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}},
	}
	q, err := msg.Pack()
	if err != nil {
		return ""
	}
	if _, err := c.WriteToUDP(q, &net.UDPAddr{IP: ip.AsSlice(), Port: 5353}); err != nil {
		return ""
	}
	buf := make([]byte, 9000)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return ""
	}
	var p dnsmessage.Parser
	if _, err := p.Start(buf[:n]); err != nil {
		return ""
	}
	_ = p.SkipAllQuestions()
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return ""
		}
		if h.Type == dnsmessage.TypePTR {
			r, err := p.PTRResource()
			if err == nil {
				return strings.TrimSuffix(r.PTR.String(), ".")
			}
		}
		_ = p.SkipAnswer()
	}
}
