// Package netflow is a NetFlow v5 / v9 / IPFIX collector. Point a
// router, firewall or switch at the OctoLAN laptop on UDP 2055 and it
// aggregates conversations, top talkers, applications and protocol mix.
package netflow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/s835773/OctoLAN/internal/model"
	"github.com/s835773/OctoLAN/internal/store"
)

const (
	maxConversations = 50000
	seriesBucket     = 5 * time.Second
	seriesLen        = 360 // 30 minutes
)

type convKey struct {
	src, dst     netip.Addr
	sport, dport uint16
	proto        uint8
}

type conv struct {
	bytes, packets uint64
	exporter       string
	last           time.Time
}

type tmplKey struct {
	exporter string
	domain   uint32
	id       uint16
}

type field struct {
	typ, length uint16
	enterprise  bool
}

// Collector receives and aggregates flows.
type Collector struct {
	st   *store.Store
	addr string

	mu        sync.Mutex
	conn      *net.UDPConn
	conv      map[convKey]*conv
	templates map[tmplKey][]field
	hosts     map[netip.Addr]*model.Talker
	apps      map[string]*model.Talker
	protos    map[string]uint64
	exporters map[string]uint64
	versions  map[string]uint64
	errs      map[string]uint64
	totalB    uint64
	totalP    uint64
	totalF    uint64
	series    []model.RatePoint
	bucketB   uint64
	bucketAt  time.Time
	observed  map[netip.Addr]bool
	done      chan struct{}
}

// Start listens on addr (e.g. ":2055").
func Start(st *store.Store, addr string) (*Collector, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, fmt.Errorf("netflow listen %s: %w", addr, err)
	}
	_ = conn.SetReadBuffer(8 << 20)
	c := &Collector{
		st: st, addr: addr, conn: conn,
		conv: map[convKey]*conv{}, templates: map[tmplKey][]field{},
		hosts: map[netip.Addr]*model.Talker{}, apps: map[string]*model.Talker{},
		protos: map[string]uint64{}, exporters: map[string]uint64{}, versions: map[string]uint64{},
		errs: map[string]uint64{}, bucketAt: time.Now().Truncate(seriesBucket),
		observed: map[netip.Addr]bool{}, done: make(chan struct{}),
	}
	go c.loop()
	go c.ticker()
	return c, nil
}

// Stop closes the listener.
func (c *Collector) Stop() {
	if c == nil {
		return
	}
	c.conn.Close()
	<-c.done
}

func (c *Collector) ticker() {
	t := time.NewTicker(seriesBucket)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			c.mu.Lock()
			c.rollLocked(time.Now())
			c.mu.Unlock()
		}
	}
}

func (c *Collector) rollLocked(now time.Time) {
	for !c.bucketAt.Add(seriesBucket).After(now) {
		bps := float64(c.bucketB*8) / seriesBucket.Seconds()
		c.series = append(c.series, model.RatePoint{T: c.bucketAt.UnixMilli(), Value: bps})
		if len(c.series) > seriesLen {
			c.series = c.series[len(c.series)-seriesLen:]
		}
		c.bucketB = 0
		c.bucketAt = c.bucketAt.Add(seriesBucket)
	}
}

func (c *Collector) loop() {
	defer close(c.done)
	buf := make([]byte, 65535)
	for {
		n, from, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		exp := from.IP.String()
		c.mu.Lock()
		first := c.exporters[exp] == 0
		c.exporters[exp]++
		if err := c.parse(buf[:n], exp); err != nil {
			c.errs[err.Error()]++
		}
		c.mu.Unlock()
		if first {
			c.st.AddEvent(model.SevInfo, "netflow", "Receiving flow exports from "+exp, "")
			c.st.Observe(exp, "", model.SrcNetFlow, func(d *model.Device) {
				d.Notes = appendNote(d.Notes, "flow exporter")
			})
		}
	}
}

func appendNote(n, s string) string {
	if n == "" {
		return s
	}
	if len(n) >= len(s) && contains(n, s) {
		return n
	}
	return n + "; " + s
}

func contains(a, b string) bool {
	for i := 0; i+len(b) <= len(a); i++ {
		if a[i:i+len(b)] == b {
			return true
		}
	}
	return false
}

func (c *Collector) parse(b []byte, exp string) error {
	if len(b) < 4 {
		return errors.New("short packet")
	}
	switch v := binary.BigEndian.Uint16(b[0:2]); v {
	case 5:
		c.versions["NetFlow v5"]++
		return c.parseV5(b, exp)
	case 9:
		c.versions["NetFlow v9"]++
		return c.parseV9(b, exp)
	case 10:
		c.versions["IPFIX"]++
		return c.parseIPFIX(b, exp)
	default:
		return fmt.Errorf("unsupported version %d", v)
	}
}

func (c *Collector) parseV5(b []byte, exp string) error {
	if len(b) < 24 {
		return errors.New("short v5 header")
	}
	count := int(binary.BigEndian.Uint16(b[2:4]))
	if len(b) < 24+count*48 {
		return errors.New("truncated v5 packet")
	}
	for i := 0; i < count; i++ {
		r := b[24+i*48:]
		c.record(flowRec{
			src:   netip.AddrFrom4([4]byte(r[0:4])),
			dst:   netip.AddrFrom4([4]byte(r[4:8])),
			pkts:  uint64(binary.BigEndian.Uint32(r[16:20])),
			bytes: uint64(binary.BigEndian.Uint32(r[20:24])),
			sport: binary.BigEndian.Uint16(r[32:34]),
			dport: binary.BigEndian.Uint16(r[34:36]),
			proto: r[38],
		}, exp)
	}
	return nil
}

func (c *Collector) parseV9(b []byte, exp string) error {
	if len(b) < 20 {
		return errors.New("short v9 header")
	}
	domain := binary.BigEndian.Uint32(b[16:20])
	return c.parseSets(b[20:], exp, domain, false)
}

func (c *Collector) parseIPFIX(b []byte, exp string) error {
	if len(b) < 16 {
		return errors.New("short IPFIX header")
	}
	l := int(binary.BigEndian.Uint16(b[2:4]))
	if l > len(b) || l < 16 {
		l = len(b)
	}
	domain := binary.BigEndian.Uint32(b[12:16])
	return c.parseSets(b[16:l], exp, domain, true)
}

// parseSets walks FlowSets (v9) / Sets (IPFIX).
func (c *Collector) parseSets(b []byte, exp string, domain uint32, ipfix bool) error {
	tmplSet, optSet := uint16(0), uint16(1)
	if ipfix {
		tmplSet, optSet = 2, 3
	}
	for len(b) >= 4 {
		id := binary.BigEndian.Uint16(b[0:2])
		l := int(binary.BigEndian.Uint16(b[2:4]))
		if l < 4 || l > len(b) {
			return errors.New("bad set length")
		}
		body := b[4:l]
		b = b[l:]
		switch {
		case id == tmplSet:
			c.parseTemplates(body, exp, domain, ipfix)
		case id == optSet:
			// Options templates (sampling info etc.) are not needed.
		case id >= 256:
			fields, ok := c.templates[tmplKey{exp, domain, id}]
			if !ok {
				c.errs["data before template (waiting for exporter to resend)"]++
				continue
			}
			c.parseData(body, fields, exp)
		}
	}
	return nil
}

func (c *Collector) parseTemplates(b []byte, exp string, domain uint32, ipfix bool) {
	for len(b) >= 4 {
		id := binary.BigEndian.Uint16(b[0:2])
		count := int(binary.BigEndian.Uint16(b[2:4]))
		b = b[4:]
		var fields []field
		for i := 0; i < count; i++ {
			if len(b) < 4 {
				return
			}
			f := field{typ: binary.BigEndian.Uint16(b[0:2]), length: binary.BigEndian.Uint16(b[2:4])}
			b = b[4:]
			if ipfix && f.typ&0x8000 != 0 {
				f.enterprise = true
				f.typ &^= 0x8000
				if len(b) < 4 {
					return
				}
				b = b[4:] // enterprise number
			}
			fields = append(fields, f)
		}
		if id >= 256 && count > 0 {
			c.templates[tmplKey{exp, domain, id}] = fields
		}
	}
}

type flowRec struct {
	src, dst     netip.Addr
	sport, dport uint16
	proto        uint8
	bytes, pkts  uint64
}

func beUint(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

func (c *Collector) parseData(b []byte, fields []field, exp string) {
	for len(b) > 0 {
		var r flowRec
		before := len(b)
		for _, f := range fields {
			l := int(f.length)
			if l == 0xffff { // IPFIX variable length
				if len(b) < 1 {
					return
				}
				l = int(b[0])
				b = b[1:]
				if l == 255 {
					if len(b) < 2 {
						return
					}
					l = int(binary.BigEndian.Uint16(b[0:2]))
					b = b[2:]
				}
			}
			if l > len(b) {
				return // padding or truncation
			}
			v := b[:l]
			b = b[l:]
			if f.enterprise {
				continue
			}
			switch f.typ {
			case 1, 85: // octetDeltaCount, octetTotalCount
				r.bytes = beUint(v)
			case 2, 86: // packetDeltaCount, packetTotalCount
				r.pkts = beUint(v)
			case 4:
				if l >= 1 {
					r.proto = v[0]
				}
			case 7:
				r.sport = uint16(beUint(v))
			case 11:
				r.dport = uint16(beUint(v))
			case 8:
				if l == 4 {
					r.src = netip.AddrFrom4([4]byte(v))
				}
			case 12:
				if l == 4 {
					r.dst = netip.AddrFrom4([4]byte(v))
				}
			case 27:
				if l == 16 {
					r.src = netip.AddrFrom16([16]byte(v))
				}
			case 28:
				if l == 16 {
					r.dst = netip.AddrFrom16([16]byte(v))
				}
			case 23: // OUT_BYTES (v9) when IN_BYTES absent
				if r.bytes == 0 {
					r.bytes = beUint(v)
				}
			}
		}
		if len(b) == before {
			return // zero-length template; avoid spinning
		}
		if !r.src.IsValid() || !r.dst.IsValid() {
			if len(b) < 4 {
				return
			}
			continue
		}
		c.record(r, exp)
	}
}

func protoName(p uint8) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 58:
		return "ICMPv6"
	case 89:
		return "OSPF"
	case 132:
		return "SCTP"
	}
	return fmt.Sprintf("IP/%d", p)
}

var appPorts = map[uint16]string{
	20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
	80: "HTTP", 88: "Kerberos", 110: "POP3", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
	143: "IMAP", 161: "SNMP", 162: "SNMP-trap", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
	104: "DICOM", 500: "IKE", 514: "Syslog", 554: "RTSP", 587: "SMTP", 636: "LDAPS", 853: "DNS-over-TLS", 993: "IMAPS", 995: "POP3S",
	1194: "OpenVPN", 1433: "MSSQL", 1723: "PPTP", 1812: "RADIUS", 1900: "SSDP", 2049: "NFS",
	3306: "MySQL", 3389: "RDP", 3478: "STUN/Teams", 4500: "IPsec-NAT", 5060: "SIP", 5061: "SIP-TLS",
	5222: "XMPP", 5353: "mDNS", 5432: "Postgres", 5900: "VNC", 8080: "HTTP-alt", 8443: "HTTPS-alt",
	9100: "Printing", 51820: "WireGuard",
}

func appFor(r flowRec) string {
	lo, hi := r.sport, r.dport
	if hi < lo {
		lo, hi = hi, lo
	}
	if r.proto == 6 || r.proto == 17 {
		if n, ok := appPorts[lo]; ok {
			return n
		}
		if n, ok := appPorts[hi]; ok {
			return n
		}
		if lo == 0 {
			return protoName(r.proto)
		}
		return fmt.Sprintf("%s/%d", protoName(r.proto), lo)
	}
	return protoName(r.proto)
}

func (c *Collector) record(r flowRec, exp string) {
	r.src, r.dst = r.src.Unmap(), r.dst.Unmap()
	c.totalF++
	c.totalB += r.bytes
	c.totalP += r.pkts
	c.bucketB += r.bytes
	c.protos[protoName(r.proto)] += r.bytes

	k := convKey{r.src, r.dst, r.sport, r.dport, r.proto}
	cv := c.conv[k]
	if cv == nil {
		if len(c.conv) >= maxConversations {
			c.evictLocked()
		}
		cv = &conv{}
		c.conv[k] = cv
	}
	cv.bytes += r.bytes
	cv.packets += r.pkts
	cv.exporter = exp
	cv.last = time.Now()

	for _, h := range []netip.Addr{r.src, r.dst} {
		t := c.hosts[h]
		if t == nil {
			t = &model.Talker{Key: h.String()}
			c.hosts[h] = t
		}
		t.Bytes += r.bytes
		t.Packets += r.pkts
		// Internal hosts seen in flows exist even if they're on another
		// VLAN we can't scan; record them (not marked alive).
		if h.IsPrivate() && !c.observed[h] && len(c.observed) < 20000 {
			c.observed[h] = true
			ip := h.String()
			go c.st.Observe(ip, "", model.SrcNetFlow, nil)
		}
	}
	app := appFor(r)
	a := c.apps[app]
	if a == nil {
		a = &model.Talker{Key: app}
		c.apps[app] = a
	}
	a.Bytes += r.bytes
	a.Packets += r.pkts
}

func (c *Collector) evictLocked() {
	// Drop the smallest 10% of conversations.
	type kv struct {
		k convKey
		b uint64
	}
	all := make([]kv, 0, len(c.conv))
	for k, v := range c.conv {
		all = append(all, kv{k, v.bytes})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].b < all[j].b })
	for i := 0; i < len(all)/10; i++ {
		delete(c.conv, all[i].k)
	}
}

// Summary returns the dashboard view.
func (c *Collector) Summary() model.FlowSummary {
	if c == nil {
		return model.FlowSummary{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rollLocked(time.Now())
	s := model.FlowSummary{
		Listening: true, ListenAddr: c.addr,
		Exporters: copyMap(c.exporters), Protocols: copyMap(c.protos), Errors: copyMap(c.errs),
		Versions: copyMap(c.versions), TotalBytes: c.totalB, TotalPackets: c.totalP, TotalFlows: c.totalF,
		Series: append([]model.RatePoint(nil), c.series...),
	}
	hosts := make([]model.Talker, 0, len(c.hosts))
	for _, t := range c.hosts {
		hosts = append(hosts, *t)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Bytes > hosts[j].Bytes })
	if len(hosts) > 25 {
		hosts = hosts[:25]
	}
	s.TopTalkers = hosts
	apps := make([]model.Talker, 0, len(c.apps))
	for _, t := range c.apps {
		apps = append(apps, *t)
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].Bytes > apps[j].Bytes })
	if len(apps) > 20 {
		apps = apps[:20]
	}
	s.TopApps = apps
	convs := make([]model.Flow, 0, len(c.conv))
	for k, v := range c.conv {
		convs = append(convs, model.Flow{Src: k.src.String(), Dst: k.dst.String(), SrcPort: int(k.sport),
			DstPort: int(k.dport), Proto: int(k.proto), Bytes: v.bytes, Packets: v.packets,
			Exporter: v.exporter, LastSeen: v.last})
	}
	sort.Slice(convs, func(i, j int) bool { return convs[i].Bytes > convs[j].Bytes })
	if len(convs) > 100 {
		convs = convs[:100]
	}
	s.Conversations = convs
	return s
}

func copyMap(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
