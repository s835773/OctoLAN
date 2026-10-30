// Package store is the in-memory inventory every scanner writes into. It
// merges observations about the same device from many sources, keeps the
// event log, and fans out change notifications to dashboard clients.
package store

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/s835773/OctoLAN/internal/model"
	"github.com/s835773/OctoLAN/internal/oui"
)

const maxEvents = 5000

// Message is pushed to subscribers (the web UI's event stream).
type Message struct {
	Type string `json:"type"`
	Data any    `json:"data,omitempty"`
}

// Store is safe for concurrent use.
type Store struct {
	mu      sync.RWMutex
	devices map[string]*model.Device
	byMAC   map[string]string // mac -> id
	byIP    map[string]string // ip -> id
	events  []model.Event
	subnets map[string]model.Subnet
	dhcp    map[string]*model.DHCPServer
	vlans   map[int]*model.VLAN
	links   []model.Link
	finds   []model.Finding
	score   int
	grade   string
	caps    model.Capabilities
	scan    model.ScanStatus
	site    string

	// Live providers registered by long-running modules.
	FlowProvider  func() model.FlowSummary
	StormProvider func() model.StormStatus

	subMu sync.Mutex
	subs  map[chan Message]struct{}

	dirty     chan struct{}
	ipSeenMAC map[string]map[string]time.Time // ip -> macs claiming it
}

// New returns an empty store and starts its change-coalescing loop.
func New() *Store {
	s := &Store{
		devices:   map[string]*model.Device{},
		byMAC:     map[string]string{},
		byIP:      map[string]string{},
		subnets:   map[string]model.Subnet{},
		dhcp:      map[string]*model.DHCPServer{},
		vlans:     map[int]*model.VLAN{},
		subs:      map[chan Message]struct{}{},
		dirty:     make(chan struct{}, 1),
		ipSeenMAC: map[string]map[string]time.Time{},
		score:     -1,
	}
	go s.coalesce()
	return s
}

// coalesce turns bursts of device updates into at most ~3 UI pushes/sec.
func (s *Store) coalesce() {
	for range s.dirty {
		time.Sleep(300 * time.Millisecond)
		s.publish(Message{Type: "devices"})
	}
}

func (s *Store) markDirty() {
	select {
	case s.dirty <- struct{}{}:
	default:
	}
}

// Subscribe returns a channel of change messages. Call the returned func
// to unsubscribe.
func (s *Store) Subscribe() (<-chan Message, func()) {
	ch := make(chan Message, 64)
	s.subMu.Lock()
	s.subs[ch] = struct{}{}
	s.subMu.Unlock()
	return ch, func() {
		s.subMu.Lock()
		if _, ok := s.subs[ch]; ok {
			delete(s.subs, ch)
			close(ch)
		}
		s.subMu.Unlock()
	}
}

func (s *Store) publish(m Message) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- m:
		default: // slow client; it will catch up on the next refresh
		}
	}
}

// Publish sends an arbitrary message to UI subscribers.
func (s *Store) Publish(typ string, data any) { s.publish(Message{Type: typ, Data: data}) }

// NormMAC lower-cases and canonicalizes a MAC; returns "" if invalid.
func NormMAC(mac string) string {
	if mac == "" {
		return ""
	}
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return ""
	}
	if isZeroOrBroadcast(hw) {
		return ""
	}
	return hw.String()
}

func isZeroOrBroadcast(hw net.HardwareAddr) bool {
	zero, bcast := true, true
	for _, b := range hw {
		if b != 0 {
			zero = false
		}
		if b != 0xff {
			bcast = false
		}
	}
	return zero || bcast || hw[0]&0x01 != 0 // multicast MACs are never hosts
}

// Observe records that a device with this ip and/or mac exists, then lets
// fn fill in details. It returns the device id. fn runs under the store
// lock, so it must not call back into the store.
func (s *Store) Observe(ip, mac, source string, fn func(d *model.Device)) string {
	mac = NormMAC(mac)
	if ip != "" {
		if a, err := netip.ParseAddr(ip); err == nil {
			ip = a.Unmap().String()
		} else {
			ip = ""
		}
	}
	if ip == "" && mac == "" {
		return ""
	}
	now := time.Now()

	s.mu.Lock()
	var dupMsg string
	d := s.lookupLocked(ip, mac)
	if d == nil {
		id := mac
		if id == "" {
			id = "ip-" + ip
		}
		d = &model.Device{ID: id, Type: model.TypeUnknown, FirstSeen: now}
		s.devices[id] = d
	}
	if mac != "" && d.MAC == "" {
		d.MAC = mac
		s.byMAC[mac] = d.ID
		if hw, err := net.ParseMAC(mac); err == nil {
			d.Vendor = oui.Lookup(hw)
			d.RandomMAC = oui.IsLocallyAdministered(hw)
		}
	}
	if ip != "" {
		if !slices.Contains(d.IPs, ip) {
			d.IPs = append(d.IPs, ip)
			sortIPs(d.IPs)
		}
		if prev, ok := s.byIP[ip]; ok && prev != d.ID {
			// The IP moved (DHCP) or two devices claim it.
			if pd := s.devices[prev]; pd != nil && pd.MAC != "" && mac != "" && pd.MAC != mac {
				dupMsg = s.noteIPClaimLocked(ip, mac, pd.MAC, now)
			}
			if pd := s.devices[prev]; pd != nil && pd.MAC == "" {
				s.absorbLocked(d, pd)
			}
		}
		s.byIP[ip] = d.ID
	}
	if source != "" && !slices.Contains(d.Sources, source) {
		d.Sources = append(d.Sources, source)
	}
	d.LastSeen = now
	if source != model.SrcNetFlow {
		d.Alive = true
	}
	if fn != nil {
		fn(d)
	}
	id := d.ID
	s.mu.Unlock()

	if dupMsg != "" {
		s.AddEvent(model.SevHigh, "arp", dupMsg, id)
	}
	s.markDirty()
	return id
}

// noteIPClaimLocked tracks MACs answering for an IP and returns a message
// when two different MACs claim it within a short window.
func (s *Store) noteIPClaimLocked(ip, mac, other string, now time.Time) string {
	m := s.ipSeenMAC[ip]
	if m == nil {
		m = map[string]time.Time{}
		s.ipSeenMAC[ip] = m
	}
	m[mac] = now
	if t, ok := m[other]; ok && now.Sub(t) < 10*time.Minute {
		return fmt.Sprintf("Possible duplicate IP %s claimed by %s and %s", ip, other, mac)
	}
	m[other] = now
	return ""
}

// DuplicateIPs returns IPs claimed by more than one MAC recently.
func (s *Store) DuplicateIPs() map[string][]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string][]string{}
	for ip, m := range s.ipSeenMAC {
		if len(m) > 1 {
			for mac := range m {
				out[ip] = append(out[ip], mac)
			}
			sort.Strings(out[ip])
		}
	}
	return out
}

func (s *Store) lookupLocked(ip, mac string) *model.Device {
	if mac != "" {
		if id, ok := s.byMAC[mac]; ok {
			return s.devices[id]
		}
	}
	if ip != "" {
		if id, ok := s.byIP[ip]; ok {
			d := s.devices[id]
			// Reuse an IP-only record, or the same MAC. Otherwise this is a
			// different physical device that now holds the IP.
			if d != nil && (mac == "" || d.MAC == "" || d.MAC == mac) {
				return d
			}
		}
	}
	return nil
}

// absorbLocked merges an IP-only placeholder into a MAC-keyed device.
func (s *Store) absorbLocked(dst, src *model.Device) {
	if dst == src {
		return
	}
	for _, ip := range src.IPs {
		if !slices.Contains(dst.IPs, ip) {
			dst.IPs = append(dst.IPs, ip)
		}
		s.byIP[ip] = dst.ID
	}
	sortIPs(dst.IPs)
	for _, so := range src.Sources {
		if !slices.Contains(dst.Sources, so) {
			dst.Sources = append(dst.Sources, so)
		}
	}
	if dst.Hostname == "" {
		dst.Hostname = src.Hostname
	}
	for _, n := range src.Names {
		addName(dst, n)
	}
	if dst.RTTMicro == 0 || (src.RTTMicro > 0 && src.RTTMicro < dst.RTTMicro) {
		dst.RTTMicro = src.RTTMicro
	}
	if dst.TTL == 0 {
		dst.TTL = src.TTL
	}
	if len(dst.Ports) == 0 {
		dst.Ports = src.Ports
	}
	if dst.SNMP == nil {
		dst.SNMP = src.SNMP
	}
	if dst.SMB == nil {
		dst.SMB = src.SMB
	}
	if len(dst.TLS) == 0 {
		dst.TLS = src.TLS
	}
	if src.FirstSeen.Before(dst.FirstSeen) {
		dst.FirstSeen = src.FirstSeen
	}
	if dst.Type == model.TypeUnknown {
		dst.Type = src.Type
	}
	if dst.OS.Confidence < src.OS.Confidence {
		dst.OS = src.OS
	}
	delete(s.devices, src.ID)
}

// Get returns a copy of one device.
func (s *Store) Get(id string) *model.Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d := s.devices[id]
	if d == nil {
		return nil
	}
	return clone(d)
}

// FindByIP returns the device id currently holding ip.
func (s *Store) FindByIP(ip string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byIP[ip]
}

// FindByMAC returns the device id for mac.
func (s *Store) FindByMAC(mac string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byMAC[NormMAC(mac)]
}

// Update runs fn on an existing device under lock.
func (s *Store) Update(id string, fn func(d *model.Device)) bool {
	s.mu.Lock()
	d := s.devices[id]
	if d != nil {
		fn(d)
	}
	s.mu.Unlock()
	if d != nil {
		s.markDirty()
	}
	return d != nil
}

// Devices returns copies of all devices sorted by IP.
func (s *Store) Devices() []*model.Device {
	s.mu.RLock()
	out := make([]*model.Device, 0, len(s.devices))
	for _, d := range s.devices {
		out = append(out, clone(d))
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return lessDevice(out[i], out[j]) })
	return out
}

func lessDevice(a, b *model.Device) bool {
	ai, bi := firstIP(a), firstIP(b)
	if ai.IsValid() != bi.IsValid() {
		return ai.IsValid()
	}
	if ai != bi {
		return ai.Less(bi)
	}
	return a.ID < b.ID
}

func firstIP(d *model.Device) netip.Addr {
	for _, s := range d.IPs {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			return a
		}
	}
	if len(d.IPs) > 0 {
		a, _ := netip.ParseAddr(d.IPs[0])
		return a
	}
	return netip.Addr{}
}

func sortIPs(ips []string) {
	sort.Slice(ips, func(i, j int) bool {
		a, e1 := netip.ParseAddr(ips[i])
		b, e2 := netip.ParseAddr(ips[j])
		if e1 != nil || e2 != nil {
			return ips[i] < ips[j]
		}
		if a.Is4() != b.Is4() {
			return a.Is4()
		}
		return a.Less(b)
	})
}

func clone(d *model.Device) *model.Device {
	b, _ := json.Marshal(d)
	var c model.Device
	_ = json.Unmarshal(b, &c)
	if d.SNMP != nil && c.SNMP != nil {
		c.SNMP.Community = d.SNMP.Community
	}
	return &c
}

// AddName records a name for a device and picks the best hostname.
func AddName(d *model.Device, name string) { addName(d, name) }

func addName(d *model.Device, name string) {
	name = strings.TrimSpace(strings.TrimSuffix(name, "."))
	if name == "" || net.ParseIP(name) != nil {
		return
	}
	if !slices.ContainsFunc(d.Names, func(n string) bool { return strings.EqualFold(n, name) }) {
		d.Names = append(d.Names, name)
	}
	if d.Hostname == "" || (strings.HasSuffix(d.Hostname, ".local") && !strings.HasSuffix(name, ".local")) {
		d.Hostname = name
	}
}

// AddSource appends a discovery source to the device.
func AddSource(d *model.Device, src string) {
	if !slices.Contains(d.Sources, src) {
		d.Sources = append(d.Sources, src)
	}
}

// --- events ---

// AddEvent appends to the activity log and pushes it to the UI.
func (s *Store) AddEvent(sev model.Severity, source, msg, deviceID string) {
	ev := model.Event{Time: time.Now(), Severity: sev, Source: source, Message: msg, DeviceID: deviceID}
	s.mu.Lock()
	s.events = append(s.events, ev)
	if len(s.events) > maxEvents {
		s.events = slices.Clone(s.events[len(s.events)-maxEvents:])
	}
	s.mu.Unlock()
	s.publish(Message{Type: "event", Data: ev})
}

// Logf is a convenience for info events.
func (s *Store) Logf(source, format string, args ...any) {
	s.AddEvent(model.SevInfo, source, fmt.Sprintf(format, args...), "")
}

// Events returns the newest n events (all if n<=0).
func (s *Store) Events(n int) []model.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ev := s.events
	if n > 0 && len(ev) > n {
		ev = ev[len(ev)-n:]
	}
	return slices.Clone(ev)
}

// --- subnets, DHCP, VLANs, links, findings ---

func (s *Store) AddSubnet(sn model.Subnet) {
	s.mu.Lock()
	if old, ok := s.subnets[sn.CIDR]; ok {
		if sn.Gateway == "" {
			sn.Gateway = old.Gateway
		}
		if sn.Interface == "" {
			sn.Interface = old.Interface
		}
		sn.Local = sn.Local || old.Local
	}
	s.subnets[sn.CIDR] = sn
	s.mu.Unlock()
}

func (s *Store) Subnets() []model.Subnet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Subnet, 0, len(s.subnets))
	for _, v := range s.subnets {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CIDR < out[j].CIDR })
	return out
}

// ObserveDHCPServer records a DHCP OFFER/ACK. Returns true if this server
// is new.
func (s *Store) ObserveDHCPServer(srv model.DHCPServer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.dhcp[srv.IP]
	if !ok {
		srv.Offers = 1
		srv.LastSeen = time.Now()
		s.dhcp[srv.IP] = &srv
		return true
	}
	cur.Offers++
	cur.LastSeen = time.Now()
	if srv.Router != "" {
		cur.Router = srv.Router
	}
	if len(srv.DNS) > 0 {
		cur.DNS = srv.DNS
	}
	if srv.Domain != "" {
		cur.Domain = srv.Domain
	}
	if srv.MAC != "" {
		cur.MAC = srv.MAC
	}
	return false
}

func (s *Store) DHCPServers() []model.DHCPServer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.DHCPServer, 0, len(s.dhcp))
	for _, v := range s.dhcp {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// ObserveVLAN merges a VLAN sighting.
func (s *Store) ObserveVLAN(v model.VLAN) {
	if v.ID <= 0 || v.ID > 4094 {
		return
	}
	s.mu.Lock()
	cur, ok := s.vlans[v.ID]
	if !ok {
		c := v
		s.vlans[v.ID] = &c
		s.mu.Unlock()
		s.markDirty()
		return
	}
	if cur.Name == "" {
		cur.Name = v.Name
	}
	if v.Tagged {
		cur.Tagged = true
	}
	if !strings.Contains(cur.Source, v.Source) {
		cur.Source += "," + v.Source
	}
	for _, p := range v.Ports {
		if !slices.Contains(cur.Ports, p) {
			cur.Ports = append(cur.Ports, p)
		}
	}
	s.mu.Unlock()
}

func (s *Store) VLANs() []model.VLAN {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.VLAN, 0, len(s.vlans))
	for _, v := range s.vlans {
		c := *v
		c.Ports = slices.Clone(v.Ports)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) SetLinks(l []model.Link) {
	s.mu.Lock()
	s.links = l
	s.mu.Unlock()
	s.publish(Message{Type: "topology"})
}

func (s *Store) Links() []model.Link {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.links)
}

func (s *Store) SetFindings(f []model.Finding, score int, grade string) {
	s.mu.Lock()
	s.finds, s.score, s.grade = f, score, grade
	s.mu.Unlock()
	s.publish(Message{Type: "findings"})
}

func (s *Store) Findings() ([]model.Finding, int, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.finds), s.score, s.grade
}

// --- capabilities, scan status, site ---

func (s *Store) SetCaps(c model.Capabilities) {
	s.mu.Lock()
	s.caps = c
	s.mu.Unlock()
}

func (s *Store) Caps() model.Capabilities {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.caps
}

func (s *Store) SetSite(name string) {
	s.mu.Lock()
	s.site = name
	s.mu.Unlock()
}

func (s *Store) Site() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.site
}

// UpdateScan mutates the scan status and pushes it to the UI.
func (s *Store) UpdateScan(fn func(st *model.ScanStatus)) {
	s.mu.Lock()
	fn(&s.scan)
	st := s.scan
	st.Phases = slices.Clone(s.scan.Phases)
	s.mu.Unlock()
	s.publish(Message{Type: "scan", Data: st})
}

func (s *Store) Scan() model.ScanStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := s.scan
	st.Phases = slices.Clone(s.scan.Phases)
	return st
}

// --- persistence ---

// Snapshot captures the full current state.
func (s *Store) Snapshot(version string) model.Snapshot {
	finds, score, grade := s.Findings()
	snap := model.Snapshot{
		Version:     version,
		Site:        s.Site(),
		Generated:   time.Now(),
		Caps:        s.Caps(),
		Subnets:     s.Subnets(),
		Devices:     s.Devices(),
		Links:       s.Links(),
		Findings:    finds,
		Score:       score,
		Grade:       grade,
		Events:      s.Events(1000),
		DHCPServers: s.DHCPServers(),
		VLANs:       s.VLANs(),
		Scan:        s.Scan(),
	}
	snap.Collector = snap.Caps.Hostname
	if s.FlowProvider != nil {
		snap.Flows = s.FlowProvider()
	}
	if s.StormProvider != nil {
		snap.Storm = s.StormProvider()
	}
	if snap.Scan.Config != nil {
		c := *snap.Scan.Config
		c.Communities = nil // secrets stay in memory only
		c.SNMPv3 = nil
		snap.Scan.Config = &c
	}
	return snap
}

// Save writes a snapshot as JSON.
func (s *Store) Save(path, version string) error {
	snap := s.Snapshot(version)
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadSnapshot reads a saved snapshot from disk.
func LoadSnapshot(path string) (*model.Snapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var snap model.Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &snap, nil
}

// Restore loads a snapshot into an empty store (used to reopen a site).
func (s *Store) Restore(snap *model.Snapshot) {
	s.mu.Lock()
	s.site = snap.Site
	for _, d := range snap.Devices {
		d.Alive = false
		s.devices[d.ID] = d
		if d.MAC != "" {
			s.byMAC[d.MAC] = d.ID
		}
		for _, ip := range d.IPs {
			s.byIP[ip] = d.ID
		}
	}
	for _, sn := range snap.Subnets {
		s.subnets[sn.CIDR] = sn
	}
	for i := range snap.DHCPServers {
		srv := snap.DHCPServers[i]
		s.dhcp[srv.IP] = &srv
	}
	for i := range snap.VLANs {
		v := snap.VLANs[i]
		s.vlans[v.ID] = &v
	}
	s.links = snap.Links
	s.finds, s.score, s.grade = snap.Findings, snap.Score, snap.Grade
	s.events = snap.Events
	s.scan = snap.Scan
	s.scan.Running = false
	s.mu.Unlock()
	s.markDirty()
}
