package discovery

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/s835773/OctoLAN/internal/capture"
	"github.com/s835773/OctoLAN/internal/model"
)

// DefaultPorts are the TCP ports an MSP assessment cares about: remote
// access, management planes, file sharing, databases, printers, cameras,
// VoIP and known-risky legacy services.
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445,
	465, 502, 515, 548, 554, 587, 631, 636, 873, 902, 993, 995, 1433, 1521,
	1723, 1883, 2049, 2375, 3000, 3128, 3260, 3306, 3389, 4786, 5000, 5001,
	5060, 5432, 5900, 5985, 5986, 6379, 7547, 8000, 8006, 8080, 8081, 8291,
	8443, 8888, 9000, 9100, 9200, 9443, 10000, 27017,
}

// DiscoveryPorts are used for "TCP ping" of hosts that ignore ICMP.
var DiscoveryPorts = []int{445, 3389, 80, 443, 22, 135, 139, 8080, 9100, 62078}

// ServiceNames labels well-known ports.
var ServiceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 81: "http-alt",
	88: "kerberos", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
	389: "ldap", 443: "https", 445: "smb", 465: "smtps", 502: "modbus", 515: "lpd", 548: "afp",
	554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync", 902: "vmware-auth",
	993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp", 1883: "mqtt",
	2049: "nfs", 2375: "docker", 3000: "http-dev", 3128: "squid", 3260: "iscsi", 3306: "mysql",
	3389: "rdp", 4786: "cisco-smart-install", 5000: "upnp/synology", 5001: "synology-https",
	5060: "sip", 5432: "postgres", 5900: "vnc", 5985: "winrm", 5986: "winrm-https",
	6379: "redis", 7547: "tr-069", 8000: "http-alt", 8006: "proxmox", 8080: "http-proxy",
	8081: "http-alt", 8291: "mikrotik-winbox", 8443: "https-alt", 8888: "http-alt",
	9000: "http-alt", 9100: "jetdirect", 9200: "elasticsearch", 9443: "https-alt",
	10000: "webmin", 27017: "mongodb", 62078: "iphone-sync", 161: "snmp",
}

var tlsPorts = map[int]bool{443: true, 465: true, 636: true, 993: true, 995: true, 5001: true,
	5986: true, 8006: true, 8443: true, 9443: true, 10000: true}
var httpPorts = map[int]bool{80: true, 81: true, 3000: true, 5000: true, 8000: true, 8080: true,
	8081: true, 8888: true, 9000: true}

// ParsePorts turns "default", "top" or "22,80,1000-1100" into a list.
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(strings.ToLower(spec))
	switch spec {
	case "", "default":
		return DefaultPorts, nil
	case "none":
		return nil, nil
	case "top", "extended":
		set := map[int]bool{}
		for _, p := range DefaultPorts {
			set[p] = true
		}
		for p := 1; p <= 1024; p++ {
			set[p] = true
		}
		out := make([]int, 0, len(set))
		for p := range set {
			out = append(out, p)
		}
		sort.Ints(out)
		return out, nil
	}
	set := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("bad port %q", part)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
				return nil, fmt.Errorf("bad port range %q", part)
			}
		}
		if a < 1 || b > 65535 || b < a {
			return nil, fmt.Errorf("bad port range %q", part)
		}
		for p := a; p <= b; p++ {
			set[p] = true
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// PortHit is an open port found by ConnectScan.
type PortHit struct {
	IP   netip.Addr
	Port int
}

// ConnectScan does a full TCP connect scan with bounded concurrency. It
// needs no privileges on any OS.
func ConnectScan(ctx context.Context, hosts []netip.Addr, ports []int, workers int, timeout time.Duration, progress *atomic.Int64, onOpen func(PortHit)) {
	if workers <= 0 {
		workers = 256
	}
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}
	type job struct {
		ip   netip.Addr
		port int
	}
	jobs := make(chan job, workers)
	var wg sync.WaitGroup
	d := net.Dialer{Timeout: timeout}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if progress != nil {
					progress.Add(1)
				}
				if ctx.Err() != nil {
					continue
				}
				c, err := d.DialContext(ctx, "tcp4", netip.AddrPortFrom(j.ip, uint16(j.port)).String())
				if err == nil {
					c.Close()
					onOpen(PortHit{IP: j.ip, Port: j.port})
				}
			}
		}()
	}
	// Interleave hosts so one slow host doesn't stall a batch.
	for _, p := range ports {
		for _, ip := range hosts {
			select {
			case jobs <- job{ip, p}:
			case <-ctx.Done():
			}
			if ctx.Err() != nil {
				break
			}
		}
	}
	close(jobs)
	wg.Wait()
}

// TCPPing reports hosts with any of DiscoveryPorts open or actively
// refusing (an RST also proves a host is alive).
func TCPPing(ctx context.Context, hosts []netip.Addr, workers int, timeout time.Duration, onAlive func(netip.Addr, int)) {
	var mu sync.Mutex
	alive := map[netip.Addr]bool{}
	type job struct {
		ip   netip.Addr
		port int
	}
	jobs := make(chan job, workers)
	var wg sync.WaitGroup
	d := net.Dialer{Timeout: timeout}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				mu.Lock()
				done := alive[j.ip]
				mu.Unlock()
				if done || ctx.Err() != nil {
					continue
				}
				c, err := d.DialContext(ctx, "tcp4", netip.AddrPortFrom(j.ip, uint16(j.port)).String())
				open := err == nil
				if open {
					c.Close()
				}
				if open || (err != nil && isRefused(err)) {
					mu.Lock()
					first := !alive[j.ip]
					alive[j.ip] = true
					mu.Unlock()
					if first {
						port := 0
						if open {
							port = j.port
						}
						onAlive(j.ip, port)
					}
				}
			}
		}()
	}
	for _, p := range DiscoveryPorts {
		for _, ip := range hosts {
			select {
			case jobs <- job{ip, p}:
			case <-ctx.Done():
			}
		}
	}
	close(jobs)
	wg.Wait()
}

func isRefused(err error) bool {
	s := err.Error()
	return strings.Contains(s, "refused") || strings.Contains(s, "actively refused")
}

// ---- SYN-ACK fingerprint sniffer ----

// StackTraits are TCP/IP fields from a host's SYN-ACK.
type StackTraits struct {
	TTL    int
	Window int
	DF     bool
	MSS    int
}

// SynAckSniffer watches a capture hub for SYN-ACKs from scanned hosts
// while ConnectScan runs. The handshake our OS performs gives us the
// remote stack's initial window, TTL, DF bit and MSS for free.
type SynAckSniffer struct {
	mu     sync.Mutex
	traits map[netip.Addr]StackTraits
	stop   func()
	done   chan struct{}
}

// StartSynAckSniffer subscribes to hub; call Stop to get results.
func StartSynAckSniffer(hub *capture.Hub) *SynAckSniffer {
	s := &SynAckSniffer{traits: map[netip.Addr]StackTraits{}, done: make(chan struct{})}
	ch, unsub := hub.Subscribe("synack", 8192)
	s.stop = unsub
	go func() {
		defer close(s.done)
		for p := range ch {
			ip, t, ok := parseSynAck(p.Data)
			if !ok {
				continue
			}
			s.mu.Lock()
			if _, exists := s.traits[ip]; !exists {
				s.traits[ip] = t
			}
			s.mu.Unlock()
		}
	}()
	return s
}

// Stop ends sniffing and returns traits per host.
func (s *SynAckSniffer) Stop() map[netip.Addr]StackTraits {
	if s == nil {
		return nil
	}
	s.stop()
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.traits
}

func parseSynAck(f []byte) (netip.Addr, StackTraits, bool) {
	off := 12
	if len(f) < 34 {
		return netip.Addr{}, StackTraits{}, false
	}
	et := uint16(f[off])<<8 | uint16(f[off+1])
	for et == 0x8100 && len(f) >= off+6 {
		off += 4
		et = uint16(f[off])<<8 | uint16(f[off+1])
	}
	ipb := f[off+2:]
	if et != 0x0800 || len(ipb) < 20 || ipb[0]>>4 != 4 || ipb[9] != 6 {
		return netip.Addr{}, StackTraits{}, false
	}
	ihl := int(ipb[0]&0xf) * 4
	if len(ipb) < ihl+20 {
		return netip.Addr{}, StackTraits{}, false
	}
	tcp := ipb[ihl:]
	flags := tcp[13]
	if flags&0x12 != 0x12 { // SYN+ACK
		return netip.Addr{}, StackTraits{}, false
	}
	t := StackTraits{
		TTL:    int(ipb[8]),
		DF:     ipb[6]&0x40 != 0,
		Window: int(tcp[14])<<8 | int(tcp[15]),
	}
	doff := int(tcp[12]>>4) * 4
	if doff > 20 && len(tcp) >= doff {
		opts := tcp[20:doff]
		for i := 0; i < len(opts); {
			switch opts[i] {
			case 0:
				i = len(opts)
			case 1:
				i++
			default:
				if i+1 >= len(opts) || opts[i+1] < 2 {
					i = len(opts)
					continue
				}
				if opts[i] == 2 && opts[i+1] == 4 && i+3 < len(opts) {
					t.MSS = int(opts[i+2])<<8 | int(opts[i+3])
				}
				i += int(opts[i+1])
			}
		}
	}
	return netip.AddrFrom4([4]byte(ipb[12:16])), t, true
}

// ---- banners & service probes ----

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)

// GrabBanner reads a service greeting or sends a light protocol probe.
func GrabBanner(ctx context.Context, ip netip.Addr, port int, timeout time.Duration) string {
	if tlsPorts[port] {
		if b := httpBanner(ctx, ip, port, true, timeout); b != "" {
			return b
		}
		return ""
	}
	if httpPorts[port] {
		return httpBanner(ctx, ip, port, false, timeout)
	}
	switch port {
	case 21, 22, 23, 25, 110, 143, 587, 3306, 5900, 1883, 6379, 8291:
	default:
		return ""
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp4", netip.AddrPortFrom(ip, uint16(port)).String())
	if err != nil {
		return ""
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout + 700*time.Millisecond))
	if port == 6379 {
		_, _ = c.Write([]byte("PING\r\n"))
	}
	buf := make([]byte, 512)
	n, _ := io.ReadAtLeast(c, buf, 1)
	return cleanBanner(buf[:n], port)
}

func cleanBanner(b []byte, port int) string {
	if port == 23 {
		// Strip telnet IAC negotiation.
		var out []byte
		for i := 0; i < len(b); i++ {
			if b[i] == 0xff && i+2 < len(b) {
				i += 2
				continue
			}
			out = append(out, b[i])
		}
		b = out
	}
	if port == 3306 && len(b) > 5 {
		// MySQL handshake: version string after 5 header bytes.
		end := 5
		for end < len(b) && b[end] != 0 {
			end++
		}
		return "MySQL " + string(b[5:end])
	}
	s := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return ' '
		}
		if r < 32 || r == 0xfffd {
			return -1
		}
		return r
	}, string(b))
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

func httpBanner(ctx context.Context, ip netip.Addr, port int, useTLS bool, timeout time.Duration) string {
	addr := netip.AddrPortFrom(ip, uint16(port)).String()
	d := &net.Dialer{Timeout: timeout}
	var c net.Conn
	var err error
	if useTLS {
		c, err = (&tls.Dialer{NetDialer: d, Config: &tls.Config{InsecureSkipVerify: true}}).DialContext(ctx, "tcp4", addr)
	} else {
		c, err = d.DialContext(ctx, "tcp4", addr)
	}
	if err != nil {
		return ""
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout + 1500*time.Millisecond))
	fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: OctoLAN-assessment\r\nAccept: */*\r\n\r\n", ip)
	r := bufio.NewReader(io.LimitReader(c, 64<<10))
	status, _ := r.ReadString('\n')
	if !strings.HasPrefix(status, "HTTP/") {
		return ""
	}
	var server, location string
	for {
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" || err != nil {
			break
		}
		k, v, _ := strings.Cut(line, ":")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "server":
			server = strings.TrimSpace(v)
		case "location":
			location = strings.TrimSpace(v)
		case "www-authenticate":
			if server == "" {
				server = "auth: " + strings.TrimSpace(v)
			}
		}
	}
	body, _ := io.ReadAll(r)
	parts := []string{strings.TrimSpace(status)}
	if server != "" {
		parts = append(parts, "Server: "+server)
	}
	if m := titleRe.FindSubmatch(body); m != nil {
		parts = append(parts, "Title: "+cleanBanner(m[1], 0))
	} else if location != "" {
		parts = append(parts, "→ "+location)
	}
	return cleanBanner([]byte(strings.Join(parts, " | ")), 0)
}

// ProbeTLS fetches the certificate presented on port.
func ProbeTLS(ctx context.Context, ip netip.Addr, port int, timeout time.Duration) *model.TLSInfo {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: &tls.Config{InsecureSkipVerify: true}}
	c, err := d.DialContext(ctx, "tcp4", netip.AddrPortFrom(ip, uint16(port)).String())
	if err != nil {
		return nil
	}
	defer c.Close()
	st := c.(*tls.Conn).ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil
	}
	cert := st.PeerCertificates[0]
	info := &model.TLSInfo{
		Port:     port,
		Subject:  certName(cert.Subject.CommonName, cert.DNSNames, cert.Subject.String()),
		Issuer:   certName(cert.Issuer.CommonName, nil, cert.Issuer.String()),
		NotAfter: cert.NotAfter,
		Version:  tls.VersionName(st.Version),
	}
	info.SelfSigned = cert.CheckSignatureFrom(cert) == nil ||
		(cert.Issuer.String() == cert.Subject.String())
	return info
}

func certName(cn string, sans []string, full string) string {
	if cn != "" {
		return cn
	}
	if len(sans) > 0 {
		return sans[0]
	}
	return full
}

// IsTLSPort reports whether OctoLAN expects TLS on port.
func IsTLSPort(p int) bool { return tlsPorts[p] }
