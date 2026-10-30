// Package netutil has helpers for local interfaces, target parsing,
// default gateways and the operating system's ARP cache.
package netutil

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MaxTargets caps a single scan so a typo like /8 can't run for days.
const MaxTargets = 1 << 16

// LocalIface is a usable IPv4 interface.
type LocalIface struct {
	Iface  net.Interface
	Addr   netip.Addr
	Prefix netip.Prefix // masked network
}

// LocalIPv4 returns up, non-loopback interfaces with IPv4 addresses.
func LocalIPv4() []LocalIface {
	ifs, _ := net.Interfaces()
	var out []LocalIface
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil || ip4[0] == 169 && ip4[1] == 254 {
				continue
			}
			ones, _ := ipn.Mask.Size()
			addr := netip.AddrFrom4([4]byte(ip4))
			out = append(out, LocalIface{Iface: ifc, Addr: addr, Prefix: netip.PrefixFrom(addr, ones).Masked()})
		}
	}
	return out
}

// IfaceByName finds a local IPv4 interface by name (or display name).
func IfaceByName(name string) (LocalIface, bool) {
	for _, l := range LocalIPv4() {
		if strings.EqualFold(l.Iface.Name, name) {
			return l, true
		}
	}
	return LocalIface{}, false
}

// IfaceFor returns the local interface whose subnet contains ip.
func IfaceFor(ip netip.Addr) (LocalIface, bool) {
	for _, l := range LocalIPv4() {
		if l.Prefix.Contains(ip) {
			return l, true
		}
	}
	return LocalIface{}, false
}

// DefaultIface picks the interface holding the default route, falling back
// to the first private-range IPv4 interface.
func DefaultIface() (LocalIface, bool) {
	locals := LocalIPv4()
	if gw, err := DefaultGateway(); err == nil {
		for _, l := range locals {
			if l.Prefix.Contains(gw) {
				return l, true
			}
		}
	}
	// A UDP "connect" reveals the source address the OS would use.
	if c, err := net.Dial("udp4", "192.0.2.1:9"); err == nil {
		la := c.LocalAddr().(*net.UDPAddr)
		c.Close()
		for _, l := range locals {
			if l.Addr == netip.AddrFrom4([4]byte(la.IP.To4())) {
				return l, true
			}
		}
	}
	for _, l := range locals {
		if l.Addr.IsPrivate() {
			return l, true
		}
	}
	if len(locals) > 0 {
		return locals[0], true
	}
	return LocalIface{}, false
}

// ParseTargets expands "10.0.0.0/24, 10.0.1.5, 10.0.2.10-50,
// 10.0.3.1-10.0.3.20" into a sorted, de-duplicated address list. Network
// and broadcast addresses of prefixes shorter than /31 are skipped.
func ParseTargets(specs []string) ([]netip.Addr, error) {
	seen := map[netip.Addr]struct{}{}
	add := func(a netip.Addr) error {
		if len(seen) >= MaxTargets {
			return fmt.Errorf("too many targets (limit %d); narrow the range", MaxTargets)
		}
		seen[a] = struct{}{}
		return nil
	}
	for _, raw := range specs {
		for _, spec := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == ';' }) {
			spec = strings.TrimSpace(spec)
			if spec == "" {
				continue
			}
			switch {
			case strings.Contains(spec, "/"):
				p, err := netip.ParsePrefix(spec)
				if err != nil || !p.Addr().Is4() {
					return nil, fmt.Errorf("bad CIDR %q", spec)
				}
				p = p.Masked()
				if p.Bits() < 16 {
					return nil, fmt.Errorf("%s is too large; use /16 or smaller", spec)
				}
				first, last := PrefixRange(p)
				for a := first; ; a = a.Next() {
					if err := add(a); err != nil {
						return nil, err
					}
					if a == last {
						break
					}
				}
			case strings.Contains(spec, "-"):
				lo, hi, _ := strings.Cut(spec, "-")
				start, err := netip.ParseAddr(strings.TrimSpace(lo))
				if err != nil || !start.Is4() {
					return nil, fmt.Errorf("bad range %q", spec)
				}
				hi = strings.TrimSpace(hi)
				var end netip.Addr
				if n, err := strconv.Atoi(hi); err == nil && n >= 0 && n <= 255 {
					b := start.As4()
					b[3] = byte(n)
					end = netip.AddrFrom4(b)
				} else if end, err = netip.ParseAddr(hi); err != nil || !end.Is4() {
					return nil, fmt.Errorf("bad range %q", spec)
				}
				if end.Less(start) {
					return nil, fmt.Errorf("bad range %q (end before start)", spec)
				}
				for a := start; ; a = a.Next() {
					if err := add(a); err != nil {
						return nil, err
					}
					if a == end {
						break
					}
				}
			default:
				a, err := netip.ParseAddr(spec)
				if err != nil {
					ips, lerr := net.LookupIP(spec)
					if lerr != nil || len(ips) == 0 {
						return nil, fmt.Errorf("bad target %q", spec)
					}
					for _, ip := range ips {
						if v4 := ip.To4(); v4 != nil {
							a = netip.AddrFrom4([4]byte(v4))
							break
						}
					}
					if !a.IsValid() {
						return nil, fmt.Errorf("no IPv4 address for %q", spec)
					}
				}
				if err := add(a.Unmap()); err != nil {
					return nil, err
				}
			}
		}
	}
	out := make([]netip.Addr, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out, nil
}

// PrefixRange returns the first and last usable host of p.
func PrefixRange(p netip.Prefix) (netip.Addr, netip.Addr) {
	p = p.Masked()
	base := binary.BigEndian.Uint32(p.Addr().AsSlice())
	size := uint32(1) << (32 - p.Bits())
	first, last := base, base+size-1
	if p.Bits() < 31 {
		first++
		last--
	}
	return u32(first), u32(last)
}

// HostCount is the number of usable hosts in p.
func HostCount(p netip.Prefix) int {
	if p.Bits() >= 31 {
		return 1 << (32 - p.Bits())
	}
	return (1 << (32 - p.Bits())) - 2
}

func u32(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// ScanPrefixFor shrinks very large local subnets to a /22 around addr so a
// default scan stays fast; returns the prefix unchanged otherwise.
func ScanPrefixFor(l LocalIface) netip.Prefix {
	if l.Prefix.Bits() < 22 {
		return netip.PrefixFrom(l.Addr, 22).Masked()
	}
	return l.Prefix
}

// ---- default gateway ----

// ErrNoGateway is returned when no default route could be determined.
var ErrNoGateway = errors.New("no default gateway found")

// DefaultGateway returns the IPv4 default gateway.
func DefaultGateway() (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	switch runtime.GOOS {
	case "linux":
		return linuxGateway()
	case "windows":
		out, err := exec.CommandContext(ctx, "route", "print", "-4", "0.0.0.0").Output()
		if err != nil {
			return netip.Addr{}, err
		}
		return parseWindowsRoute(out)
	default: // darwin, *bsd
		out, err := exec.CommandContext(ctx, "route", "-n", "get", "default").Output()
		if err != nil {
			return netip.Addr{}, err
		}
		for _, line := range strings.Split(string(out), "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && k == "gateway" {
				if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
					return a, nil
				}
			}
		}
	}
	return netip.Addr{}, ErrNoGateway
}

func parseWindowsRoute(out []byte) (netip.Addr, error) {
	best, bestMetric := netip.Addr{}, 1<<30
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 5 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" {
			gw, err := netip.ParseAddr(f[2])
			if err != nil {
				continue
			}
			m, _ := strconv.Atoi(f[len(f)-1])
			if m < bestMetric {
				best, bestMetric = gw, m
			}
		}
	}
	if !best.IsValid() {
		return best, ErrNoGateway
	}
	return best, nil
}

// ---- ARP cache ----

// ARPEntry is one row of the OS neighbour table.
type ARPEntry struct {
	IP    netip.Addr
	MAC   net.HardwareAddr
	Iface string
}

// ARPTable reads the operating system's ARP cache. It needs no special
// privileges and is the fallback when raw ARP isn't available.
func ARPTable() ([]ARPEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	switch runtime.GOOS {
	case "linux":
		return linuxARP()
	case "windows":
		return windowsARP()
	default:
		out, err := exec.CommandContext(ctx, "arp", "-an").Output()
		if err != nil {
			return nil, err
		}
		return parseBSDARP(out), nil
	}
}

// parseBSDARP parses "? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]".
func parseBSDARP(out []byte) []ARPEntry {
	var res []ARPEntry
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[2] != "at" {
			continue
		}
		ip, err := netip.ParseAddr(strings.Trim(f[1], "()"))
		if err != nil {
			continue
		}
		mac, err := parseLooseMAC(f[3])
		if err != nil {
			continue
		}
		e := ARPEntry{IP: ip, MAC: mac}
		for i := 4; i+1 < len(f); i++ {
			if f[i] == "on" {
				e.Iface = f[i+1]
			}
		}
		res = append(res, e)
	}
	return res
}

// parseLooseMAC accepts macOS-style "0:1:2:a:b:c" as well as normal forms.
func parseLooseMAC(s string) (net.HardwareAddr, error) {
	s = strings.ReplaceAll(s, "-", ":")
	parts := strings.Split(s, ":")
	if len(parts) == 6 {
		for i, p := range parts {
			if len(p) == 1 {
				parts[i] = "0" + p
			}
		}
		s = strings.Join(parts, ":")
	}
	hw, err := net.ParseMAC(s)
	if err != nil {
		return nil, err
	}
	allZero := true
	for _, b := range hw {
		if b != 0 {
			allZero = false
		}
	}
	if allZero || hw[0]&1 == 1 {
		return nil, errors.New("not a unicast mac")
	}
	return hw, nil
}
