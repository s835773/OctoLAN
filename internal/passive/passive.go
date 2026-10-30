// Package passive learns about the network purely by listening: ARP,
// DHCP (hostnames, vendor classes, rogue servers), mDNS/Bonjour, SSDP/UPnP,
// LLDP and CDP from the switch port we're plugged into, 802.1Q VLAN tags,
// and every host that talks on the local segment. It never transmits.
package passive

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/s835773/OcuLAN/internal/capture"
	"github.com/s835773/OcuLAN/internal/model"
	"github.com/s835773/OcuLAN/internal/netutil"
	"github.com/s835773/OcuLAN/internal/store"
)

// Stats counts what the listener has heard.
type Stats struct {
	Running  bool              `json:"running"`
	Mode     string            `json:"mode"` // capture | sockets
	Iface    string            `json:"iface,omitempty"`
	Since    time.Time         `json:"since"`
	Packets  uint64            `json:"packets"`
	Protocol map[string]uint64 `json:"protocols"`
	Note     string            `json:"note,omitempty"`
}

// Listener runs until Stop.
type Listener struct {
	st     *store.Store
	local  netutil.LocalIface
	selfID string

	mu       sync.Mutex
	counts   map[string]uint64
	packets  atomic.Uint64
	seen     map[string]time.Time
	vlanSeen map[int]bool
	since    time.Time
	mode     string
	note     string

	stops []func()
	wg    sync.WaitGroup
}

// Start listens on hub if non-nil, otherwise falls back to multicast
// sockets (mDNS + SSDP only).
func Start(st *store.Store, hub *capture.Hub, local netutil.LocalIface, selfID string) *Listener {
	l := &Listener{
		st: st, local: local, selfID: selfID,
		counts: map[string]uint64{}, seen: map[string]time.Time{}, vlanSeen: map[int]bool{},
		since: time.Now(),
	}
	if hub != nil {
		l.mode = "capture"
		ch, unsub := hub.Subscribe("passive", 16384)
		l.stops = append(l.stops, unsub)
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			for p := range ch {
				l.handleFrame(p.Data)
			}
		}()
	} else {
		l.mode = "sockets"
		l.note = "raw capture unavailable: listening to mDNS and SSDP only"
		l.startSockets()
	}
	return l
}

// Stop ends listening.
func (l *Listener) Stop() {
	for _, s := range l.stops {
		s()
	}
	l.wg.Wait()
}

// Stats returns counters for the dashboard.
func (l *Listener) Stats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := make(map[string]uint64, len(l.counts))
	for k, v := range l.counts {
		c[k] = v
	}
	return Stats{Running: true, Mode: l.mode, Iface: l.local.Iface.Name, Since: l.since,
		Packets: l.packets.Load(), Protocol: c, Note: l.note}
}

func (l *Listener) count(proto string) {
	l.mu.Lock()
	l.counts[proto]++
	l.mu.Unlock()
}

// throttle returns true the first time key is seen per interval.
func (l *Listener) throttle(key string, every time.Duration) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.seen[key]; ok && now.Sub(t) < every {
		return false
	}
	l.seen[key] = now
	if len(l.seen) > 200000 {
		for k, t := range l.seen {
			if now.Sub(t) > 10*time.Minute {
				delete(l.seen, k)
			}
		}
	}
	return true
}

func (l *Listener) handleFrame(data []byte) {
	l.packets.Add(1)
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	eth, _ := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if eth == nil {
		return
	}
	srcMAC := eth.SrcMAC.String()

	if q, ok := pkt.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q); ok {
		id := int(q.VLANIdentifier)
		l.mu.Lock()
		first := !l.vlanSeen[id]
		l.vlanSeen[id] = true
		l.mu.Unlock()
		if first {
			l.count("802.1q")
			l.st.ObserveVLAN(model.VLAN{ID: id, Source: "wire", Tagged: true})
			l.st.AddEvent(model.SevInfo, "vlan", fmt.Sprintf("Tagged 802.1Q traffic for VLAN %d heard on %s (port is a trunk or mirror)", id, l.local.Iface.Name), "")
		}
	}

	switch {
	case pkt.Layer(layers.LayerTypeLinkLayerDiscovery) != nil:
		l.count("lldp")
		l.handleLLDP(pkt, srcMAC)
		return
	case pkt.Layer(layers.LayerTypeCiscoDiscovery) != nil:
		l.count("cdp")
		l.handleCDP(pkt, srcMAC)
		return
	}

	if a, ok := pkt.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
		l.count("arp")
		if len(a.SourceProtAddress) == 4 && len(a.SourceHwAddress) == 6 {
			ip := netip.AddrFrom4([4]byte(a.SourceProtAddress))
			mac := net.HardwareAddr(a.SourceHwAddress).String()
			if !ip.IsUnspecified() && l.local.Prefix.Contains(ip) && l.throttle("arp"+ip.String()+mac, 30*time.Second) {
				l.st.Observe(ip.String(), mac, model.SrcARP, nil)
			}
		}
		return
	}

	ip4, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4 == nil {
		return
	}
	src, _ := netip.AddrFromSlice(ip4.SrcIP)
	src = src.Unmap()

	// Any local host that sends traffic proves it exists.
	if src.IsValid() && !src.IsUnspecified() && l.local.Prefix.Contains(src) && l.throttle("ip"+src.String()+srcMAC, time.Minute) {
		l.st.Observe(src.String(), srcMAC, model.SrcPassive, nil)
	}

	if udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		switch {
		case udp.SrcPort == 67 || udp.DstPort == 67 || udp.SrcPort == 68 || udp.DstPort == 68:
			if d, ok := pkt.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4); ok {
				l.count("dhcp")
				l.handleDHCP(d, src, srcMAC)
			}
		case udp.SrcPort == 5353 || udp.DstPort == 5353:
			l.count("mdns")
			if src.IsValid() && l.throttle(fmt.Sprintf("mdns%s%x", src, hash(udp.Payload)), 20*time.Second) {
				HandleMDNS(l.st, udp.Payload, src, srcMAC, l.local.Prefix.Contains(src))
			}
		case udp.DstPort == 1900 || udp.SrcPort == 1900:
			l.count("ssdp")
			if src.IsValid() && l.throttle(fmt.Sprintf("ssdp%s%x", src, hash(udp.Payload)), time.Minute) {
				HandleSSDP(l.st, udp.Payload, src, srcMAC, l.local.Prefix.Contains(src))
			}
		case udp.DstPort == 137:
			l.count("netbios")
		case udp.DstPort == 5355:
			l.count("llmnr")
		}
	}
}

func hash(b []byte) uint32 {
	var h uint32 = 2166136261
	for _, c := range b {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}

// ---- DHCP ----

func (l *Listener) handleDHCP(d *layers.DHCPv4, src netip.Addr, srcMAC string) {
	var msgType layers.DHCPMsgType
	var hostname, vendorClass, domain string
	var serverID, router, reqIP netip.Addr
	var dns []string
	for _, o := range d.Options {
		switch o.Type {
		case layers.DHCPOptMessageType:
			if len(o.Data) == 1 {
				msgType = layers.DHCPMsgType(o.Data[0])
			}
		case layers.DHCPOptHostname:
			hostname = string(o.Data)
		case layers.DHCPOptClassID:
			vendorClass = string(o.Data)
		case layers.DHCPOptServerID:
			if len(o.Data) == 4 {
				serverID = netip.AddrFrom4([4]byte(o.Data))
			}
		case layers.DHCPOptRouter:
			if len(o.Data) >= 4 {
				router = netip.AddrFrom4([4]byte(o.Data[:4]))
			}
		case layers.DHCPOptDNS:
			for i := 0; i+4 <= len(o.Data); i += 4 {
				dns = append(dns, netip.AddrFrom4([4]byte(o.Data[i:i+4])).String())
			}
		case layers.DHCPOptDomainName:
			domain = strings.TrimRight(string(o.Data), "\x00")
		case layers.DHCPOptRequestIP:
			if len(o.Data) == 4 {
				reqIP = netip.AddrFrom4([4]byte(o.Data))
			}
		}
	}
	switch msgType {
	case layers.DHCPMsgTypeOffer, layers.DHCPMsgTypeAck:
		srv := serverID
		if !srv.IsValid() {
			srv = src
		}
		if !srv.IsValid() {
			return
		}
		s := model.DHCPServer{IP: srv.String(), DNS: dns, Domain: domain}
		if srv == src {
			s.MAC = srcMAC
		}
		if router.IsValid() {
			s.Router = router.String()
		}
		if l.st.ObserveDHCPServer(s) {
			l.st.AddEvent(model.SevInfo, "dhcp", fmt.Sprintf("DHCP server %s answering (router %s, DNS %s)", s.IP, s.Router, strings.Join(dns, ", ")), "")
			if n := len(l.st.DHCPServers()); n > 1 {
				l.st.AddEvent(model.SevHigh, "dhcp", fmt.Sprintf("%d different DHCP servers are answering on this segment: possible rogue DHCP server", n), "")
			}
		}
		l.st.Observe(srv.String(), s.MAC, model.SrcDHCP, func(dev *model.Device) {
			dev.Notes = appendNote(dev.Notes, "DHCP server")
		})
	case layers.DHCPMsgTypeRequest, layers.DHCPMsgTypeDiscover, layers.DHCPMsgTypeInform:
		mac := d.ClientHWAddr.String()
		ip := reqIP
		if !d.ClientIP.IsUnspecified() {
			if a, ok := netip.AddrFromSlice(d.ClientIP); ok {
				ip = a.Unmap()
			}
		}
		ipStr := ""
		if ip.IsValid() {
			ipStr = ip.String()
		}
		if hostname == "" && vendorClass == "" {
			return
		}
		l.st.Observe(ipStr, mac, model.SrcDHCP, func(dev *model.Device) {
			if hostname != "" {
				store.AddName(dev, hostname)
			}
			if vendorClass != "" {
				applyVendorClass(dev, vendorClass)
			}
		})
	}
}

func applyVendorClass(d *model.Device, vc string) {
	lc := strings.ToLower(vc)
	ev := "DHCP vendor class " + vc
	switch {
	case strings.HasPrefix(lc, "msft"):
		setWeakOS(d, "Windows", ev)
	case strings.HasPrefix(lc, "android"):
		setWeakOS(d, "Android", ev)
		if d.Type == model.TypeUnknown {
			d.Type = model.TypeMobile
		}
	case strings.HasPrefix(lc, "dhcpcd") || strings.Contains(lc, "linux"):
		setWeakOS(d, "Linux", ev)
	case strings.Contains(lc, "cisco") || strings.Contains(lc, "aironet"):
		setWeakOS(d, "Cisco", ev)
	case strings.Contains(lc, "polycom") || strings.Contains(lc, "yealink"):
		if d.Type == model.TypeUnknown {
			d.Type = model.TypePhone
		}
	}
}

func setWeakOS(d *model.Device, fam, ev string) {
	if d.OS.Confidence < 50 {
		d.OS.Family = fam
		d.OS.Confidence = 50
	}
	for _, e := range d.OS.Evidence {
		if e == ev {
			return
		}
	}
	d.OS.Evidence = append(d.OS.Evidence, ev)
}

func appendNote(notes, n string) string {
	if strings.Contains(notes, n) {
		return notes
	}
	if notes == "" {
		return n
	}
	return notes + "; " + n
}

// ---- LLDP / CDP ----

func (l *Listener) handleLLDP(pkt gopacket.Packet, srcMAC string) {
	lldp, _ := pkt.Layer(layers.LayerTypeLinkLayerDiscovery).(*layers.LinkLayerDiscovery)
	info, _ := pkt.Layer(layers.LayerTypeLinkLayerDiscoveryInfo).(*layers.LinkLayerDiscoveryInfo)
	if lldp == nil {
		return
	}
	n := model.Neighbor{Protocol: "lldp", LocalPort: l.local.Iface.Name}
	if lldp.ChassisID.Subtype == layers.LLDPChassisIDSubTypeMACAddr && len(lldp.ChassisID.ID) == 6 {
		n.RemoteChassis = net.HardwareAddr(lldp.ChassisID.ID).String()
	} else {
		n.RemoteChassis = printable(lldp.ChassisID.ID)
	}
	if lldp.PortID.Subtype == layers.LLDPPortIDSubtypeMACAddr && len(lldp.PortID.ID) == 6 {
		n.RemotePort = net.HardwareAddr(lldp.PortID.ID).String()
	} else {
		n.RemotePort = printable(lldp.PortID.ID)
	}
	mgmtIP := ""
	if info != nil {
		n.RemoteName = info.SysName
		n.RemoteDescr = info.SysDescription
		if info.PortDescription != "" && (n.RemotePort == "" || strings.Count(n.RemotePort, ":") == 5) {
			n.RemotePort = info.PortDescription
		}
		caps := info.SysCapabilities.EnabledCap
		var cs []string
		if caps.Bridge {
			cs = append(cs, "bridge")
		}
		if caps.Router {
			cs = append(cs, "router")
		}
		if caps.WLANAP {
			cs = append(cs, "wlan-ap")
		}
		if caps.Phone {
			cs = append(cs, "telephone")
		}
		if caps.StationOnly {
			cs = append(cs, "station")
		}
		n.RemoteCaps = strings.Join(cs, ",")
		if info.MgmtAddress.Subtype == layers.IANAAddressFamilyIPV4 && len(info.MgmtAddress.Address) == 4 {
			mgmtIP = net.IP(info.MgmtAddress.Address).String()
			n.RemoteIP = mgmtIP
		}
		if d8021, err := info.Decode8021(); err == nil {
			n.NativeVLAN = int(d8021.PVID)
			for _, v := range d8021.VLANNames {
				l.st.ObserveVLAN(model.VLAN{ID: int(v.ID), Name: v.Name, Source: "lldp"})
			}
			if d8021.PVID > 0 {
				l.st.ObserveVLAN(model.VLAN{ID: int(d8021.PVID), Source: "lldp"})
			}
		}
	}
	l.recordNeighbor(n, srcMAC, mgmtIP)
}

func (l *Listener) handleCDP(pkt gopacket.Packet, srcMAC string) {
	info, _ := pkt.Layer(layers.LayerTypeCiscoDiscoveryInfo).(*layers.CiscoDiscoveryInfo)
	if info == nil {
		return
	}
	n := model.Neighbor{Protocol: "cdp", LocalPort: l.local.Iface.Name, RemoteName: info.DeviceID,
		RemotePort: info.PortID, RemoteDescr: info.Platform, NativeVLAN: int(info.NativeVLAN)}
	if info.Version != "" {
		n.RemoteDescr = info.Platform + " " + firstLine(info.Version)
	}
	var cs []string
	if info.Capabilities.L3Router {
		cs = append(cs, "router")
	}
	if info.Capabilities.L2Switch || info.Capabilities.TBBridge {
		cs = append(cs, "bridge")
	}
	if info.Capabilities.IsPhone {
		cs = append(cs, "telephone")
	}
	n.RemoteCaps = strings.Join(cs, ",")
	mgmt := ""
	for _, a := range append(info.MgmtAddresses, info.Addresses...) {
		if v4 := a.To4(); v4 != nil {
			mgmt = v4.String()
			break
		}
	}
	n.RemoteIP = mgmt
	if info.NativeVLAN > 0 {
		l.st.ObserveVLAN(model.VLAN{ID: int(info.NativeVLAN), Source: "cdp"})
	}
	l.recordNeighbor(n, srcMAC, mgmt)
}

func (l *Listener) recordNeighbor(n model.Neighbor, srcMAC, mgmtIP string) {
	key := n.Protocol + n.RemoteChassis + n.RemotePort + n.RemoteName
	first := l.throttle("nbr"+key, 365*24*time.Hour)
	chassisMAC := ""
	if _, err := net.ParseMAC(n.RemoteChassis); err == nil {
		chassisMAC = n.RemoteChassis
	}
	devMAC := chassisMAC
	if devMAC == "" && mgmtIP == "" {
		devMAC = srcMAC
	}
	id := l.st.Observe(mgmtIP, devMAC, n.Protocol, func(d *model.Device) {
		if n.RemoteName != "" {
			store.AddName(d, n.RemoteName)
		}
		caps := n.RemoteCaps
		switch {
		case strings.Contains(caps, "wlan-ap"):
			d.Type = model.TypeAccessPoint
		case strings.Contains(caps, "telephone"):
			d.Type = model.TypePhone
		case strings.Contains(caps, "router") && !strings.Contains(caps, "bridge"):
			d.Type = model.TypeRouter
		case strings.Contains(caps, "bridge"):
			d.Type = model.TypeSwitch
		}
		if n.RemoteDescr != "" && d.Model == "" {
			d.Model = firstLine(n.RemoteDescr)
			if len(d.Model) > 80 {
				d.Model = d.Model[:80]
			}
		}
	})
	if l.selfID != "" {
		l.st.Update(l.selfID, func(self *model.Device) {
			for i, e := range self.Neighbors {
				if e.Protocol == n.Protocol && e.RemoteChassis == n.RemoteChassis && e.RemotePort == n.RemotePort {
					self.Neighbors[i] = n
					return
				}
			}
			self.Neighbors = append(self.Neighbors, n)
		})
	}
	if first {
		msg := fmt.Sprintf("%s: connected to %s port %s", strings.ToUpper(n.Protocol), nonEmpty(n.RemoteName, n.RemoteChassis), n.RemotePort)
		if n.NativeVLAN > 0 {
			msg += fmt.Sprintf(" (native VLAN %d)", n.NativeVLAN)
		}
		l.st.AddEvent(model.SevInfo, n.Protocol, msg, id)
	}
}

func printable(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return -1
		}
		return r
	}, string(b))
	if s == "" && len(b) > 0 {
		return fmt.Sprintf("%x", b)
	}
	return s
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return strings.TrimSpace(s)
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
