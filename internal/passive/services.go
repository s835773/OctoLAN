package passive

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"

	"github.com/s835773/OcuLAN/internal/model"
	"github.com/s835773/OcuLAN/internal/netutil"
	"github.com/s835773/OcuLAN/internal/store"
)

const maxServices = 40

func addService(d *model.Device, s model.Service) {
	for i, e := range d.Services {
		if e.Type == s.Type && e.Name == s.Name {
			if s.Detail != "" {
				d.Services[i].Detail = s.Detail
			}
			return
		}
	}
	if len(d.Services) < maxServices {
		d.Services = append(d.Services, s)
	}
}

// HandleMDNS parses an mDNS response and attributes names, services and
// model hints to the sender. MAC is used only when the sender is on our
// segment.
func HandleMDNS(st *store.Store, payload []byte, src netip.Addr, srcMAC string, local bool) {
	var p dnsmessage.Parser
	h, err := p.Start(payload)
	if err != nil || !h.Response {
		return
	}
	_ = p.SkipAllQuestions()
	var names []string
	var svcs []model.Service
	var modelHint string
	aRecords := map[netip.Addr]string{}
	type sec struct {
		header func() (dnsmessage.ResourceHeader, error)
		skip   func() error
	}
	for _, section := range []sec{{p.AnswerHeader, p.SkipAnswer}, {p.AuthorityHeader, p.SkipAuthority}, {p.AdditionalHeader, p.SkipAdditional}} {
		for {
			rh, err := section.header()
			if err != nil {
				break
			}
			name := strings.TrimSuffix(rh.Name.String(), ".")
			switch rh.Type {
			case dnsmessage.TypeA:
				r, err := p.AResource()
				if err != nil {
					return
				}
				aRecords[netip.AddrFrom4(r.A)] = name
			case dnsmessage.TypePTR:
				r, err := p.PTRResource()
				if err != nil {
					return
				}
				target := strings.TrimSuffix(r.PTR.String(), ".")
				if strings.HasSuffix(name, ".in-addr.arpa") {
					names = append(names, target)
					continue
				}
				if name == "_services._dns-sd._udp.local" {
					svcs = append(svcs, model.Service{Type: svcType(target)})
					continue
				}
				inst := strings.TrimSuffix(target, "."+name)
				svcs = append(svcs, model.Service{Type: svcType(name), Name: unescape(inst)})
			case dnsmessage.TypeSRV:
				r, err := p.SRVResource()
				if err != nil {
					return
				}
				names = append(names, strings.TrimSuffix(r.Target.String(), "."))
			case dnsmessage.TypeTXT:
				r, err := p.TXTResource()
				if err != nil {
					return
				}
				for _, kv := range r.TXT {
					k, v, _ := strings.Cut(kv, "=")
					switch strings.ToLower(k) {
					case "md", "model", "ty", "usb_mdl", "product":
						if v != "" && modelHint == "" {
							modelHint = strings.Trim(v, "()")
						}
					}
				}
				if strings.Contains(name, "_device-info") && modelHint != "" {
					svcs = append(svcs, model.Service{Type: "_device-info._tcp", Detail: modelHint})
				}
			default:
				if section.skip() != nil {
					return
				}
			}
		}
	}
	for ip, name := range aRecords {
		mac := ""
		if ip == src && local {
			mac = srcMAC
		}
		st.Observe(ip.String(), mac, model.SrcMDNS, func(d *model.Device) { store.AddName(d, name) })
	}
	if len(names) == 0 && len(svcs) == 0 && modelHint == "" {
		return
	}
	mac := ""
	if local {
		mac = srcMAC
	}
	st.Observe(src.String(), mac, model.SrcMDNS, func(d *model.Device) {
		for _, n := range names {
			store.AddName(d, n)
		}
		for _, s := range svcs {
			addService(d, s)
		}
		if modelHint != "" && d.Model == "" {
			d.Model = modelHint
		}
	})
}

func svcType(s string) string {
	s = strings.TrimSuffix(s, ".local")
	return s
}

func unescape(s string) string {
	return strings.ReplaceAll(s, `\032`, " ")
}

// HandleSSDP parses NOTIFY / M-SEARCH responses.
func HandleSSDP(st *store.Store, payload []byte, src netip.Addr, srcMAC string, local bool) {
	if bytes.HasPrefix(payload, []byte("M-SEARCH")) {
		return // a query, not an advertisement
	}
	r := bufio.NewReader(bytes.NewReader(payload))
	first, _ := r.ReadString('\n')
	if !strings.HasPrefix(first, "NOTIFY") && !strings.HasPrefix(first, "HTTP/1.1 200") {
		return
	}
	hdr := map[string]string{}
	for {
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" || err != nil {
			break
		}
		k, v, _ := strings.Cut(line, ":")
		hdr[strings.ToUpper(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	nt := hdr["NT"]
	if nt == "" {
		nt = hdr["ST"]
	}
	if hdr["NTS"] == "ssdp:byebye" {
		return
	}
	mac := ""
	if local {
		mac = srcMAC
	}
	svc := model.Service{Type: "ssdp", Name: shortNT(nt), Detail: hdr["SERVER"]}
	st.Observe(src.String(), mac, model.SrcSSDP, func(d *model.Device) {
		addService(d, svc)
		if loc := hdr["LOCATION"]; loc != "" {
			addService(d, model.Service{Type: "upnp-location", Name: loc})
		}
	})
}

func shortNT(nt string) string {
	nt = strings.TrimPrefix(nt, "urn:schemas-upnp-org:")
	nt = strings.TrimPrefix(nt, "urn:")
	return nt
}

// ---- socket fallback & active service discovery ----

var (
	mdnsGroup = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	ssdpGroup = &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
)

func (l *Listener) startSockets() {
	ifc := l.local.Iface
	for _, grp := range []*net.UDPAddr{mdnsGroup, ssdpGroup} {
		pc, err := listenMulticast(grp, &ifc)
		if err != nil {
			continue
		}
		g := grp
		l.stops = append(l.stops, func() { pc.Close() })
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			buf := make([]byte, 9000)
			for {
				n, addr, err := pc.ReadFromUDP(buf)
				if err != nil {
					return
				}
				l.packets.Add(1)
				src, _ := netip.AddrFromSlice(addr.IP)
				src = src.Unmap()
				data := append([]byte(nil), buf[:n]...)
				if g.Port == 5353 {
					l.count("mdns")
					HandleMDNS(l.st, data, src, "", false)
				} else {
					l.count("ssdp")
					HandleSSDP(l.st, data, src, "", false)
				}
			}
		}()
	}
}

func listenMulticast(grp *net.UDPAddr, ifc *net.Interface) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: reuseControl}
	c, err := lc.ListenPacket(context.Background(), "udp4", (&net.UDPAddr{Port: grp.Port}).String())
	if err != nil {
		return nil, err
	}
	pc := ipv4.NewPacketConn(c)
	if err := pc.JoinGroup(ifc, &net.UDPAddr{IP: grp.IP}); err != nil {
		c.Close()
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

// ActiveServiceDiscovery sends one mDNS service-enumeration query and one
// SSDP M-SEARCH from an ephemeral port and records the unicast replies.
// Passive listening catches the multicast replies.
func ActiveServiceDiscovery(ctx context.Context, st *store.Store, local netutil.LocalIface, wait time.Duration) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local.Addr.AsSlice()})
	if err != nil {
		return
	}
	defer c.Close()
	if pc := ipv4.NewPacketConn(c); pc != nil {
		_ = pc.SetMulticastInterface(&local.Iface)
		_ = pc.SetMulticastTTL(2)
	}
	for _, q := range []string{"_services._dns-sd._udp.local.", "_workstation._tcp.local.", "_device-info._tcp.local.", "_ipp._tcp.local.", "_printer._tcp.local.", "_googlecast._tcp.local.", "_airplay._tcp.local.", "_smb._tcp.local.", "_ssh._tcp.local.", "_http._tcp.local."} {
		if m := mdnsQuery(q); m != nil {
			_, _ = c.WriteToUDP(m, mdnsGroup)
		}
	}
	msearch := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\nUSER-AGENT: OcuLAN/1.0 UPnP/1.1\r\n\r\n"
	_, _ = c.WriteToUDP([]byte(msearch), ssdpGroup)

	deadline := time.Now().Add(wait)
	buf := make([]byte, 9000)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		src, _ := netip.AddrFromSlice(addr.IP)
		src = src.Unmap()
		data := append([]byte(nil), buf[:n]...)
		if addr.Port == 5353 {
			HandleMDNS(st, data, src, "", false)
		} else {
			HandleSSDP(st, data, src, "", false)
		}
	}
}

func mdnsQuery(name string) []byte {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil
	}
	m := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}}}
	b, _ := m.Pack()
	return b
}

// FetchUPnPDescription downloads a device description XML (friendlyName,
// manufacturer, modelName) from an SSDP LOCATION.
func FetchUPnPDescription(ctx context.Context, url string) (friendly, manufacturer, modelName string) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	buf := make([]byte, 64<<10)
	n, _ := bufio.NewReader(resp.Body).Read(buf)
	body := string(buf[:n])
	get := func(tag string) string {
		i := strings.Index(body, "<"+tag+">")
		if i < 0 {
			return ""
		}
		j := strings.Index(body[i:], "</"+tag+">")
		if j < 0 {
			return ""
		}
		return strings.TrimSpace(body[i+len(tag)+2 : i+j])
	}
	return get("friendlyName"), get("manufacturer"), get("modelName")
}
