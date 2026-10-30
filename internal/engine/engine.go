// Package engine orchestrates an OctoLAN assessment: it owns the
// long-running monitors (passive listener, Storm Guard, NetFlow) and runs
// the scan pipeline that fills the store.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/s835773/OctoLAN/internal/assess"
	"github.com/s835773/OctoLAN/internal/capture"
	"github.com/s835773/OctoLAN/internal/discovery"
	"github.com/s835773/OctoLAN/internal/model"
	"github.com/s835773/OctoLAN/internal/netflow"
	"github.com/s835773/OctoLAN/internal/netutil"
	"github.com/s835773/OctoLAN/internal/passive"
	"github.com/s835773/OctoLAN/internal/store"
	"github.com/s835773/OctoLAN/internal/storm"
	"github.com/s835773/OctoLAN/internal/topology"
)

// Engine is safe for concurrent use.
type Engine struct {
	St      *store.Store
	Version string
	DataDir string

	mu       sync.Mutex
	cancel   context.CancelFunc
	scanDone chan struct{}
	iface    string
	hub      *capture.Hub
	passive  *passive.Listener
	storm    *storm.Guard
	flow     *netflow.Collector
	selfID   string
	warnPPS  int
	critPPS  int
}

// New creates an engine around st.
func New(st *store.Store, version, dataDir string) *Engine {
	e := &Engine{St: st, Version: version, DataDir: dataDir}
	st.FlowProvider = e.FlowSummary
	st.StormProvider = e.StormStatus
	return e
}

// SetStormThresholds overrides Storm Guard's warn/critical PPS.
func (e *Engine) SetStormThresholds(warn, crit int) {
	e.mu.Lock()
	e.warnPPS, e.critPPS = warn, crit
	e.mu.Unlock()
}

// DetectCaps inspects interfaces and privileges.
func (e *Engine) DetectCaps() model.Capabilities {
	host, _ := os.Hostname()
	c := model.Capabilities{OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: host, ICMPMode: discovery.ICMPMode()}
	gw, _ := netutil.DefaultGateway()
	for _, l := range netutil.LocalIPv4() {
		info := model.IfInfo{Name: l.Iface.Name, Display: l.Iface.Name, MAC: l.Iface.HardwareAddr.String(),
			Addrs: []string{netip.PrefixFrom(l.Addr, l.Prefix.Bits()).String()}, Up: true}
		if gw.IsValid() && l.Prefix.Contains(gw) {
			info.Gateway = gw.String()
		}
		if i := slices.IndexFunc(c.Interfaces, func(x model.IfInfo) bool { return x.Name == info.Name }); i >= 0 {
			c.Interfaces[i].Addrs = append(c.Interfaces[i].Addrs, info.Addrs...)
			continue
		}
		c.Interfaces = append(c.Interfaces, info)
	}
	if d, ok := netutil.DefaultIface(); ok {
		c.DefaultIface = d.Iface.Name
		c.RawCapture, c.CaptureNote = capture.Probe(d.Iface.Name)
	} else {
		c.CaptureNote = "no IPv4 network interface is up"
	}
	c.Privileged = c.RawCapture || c.ICMPMode == "raw"
	e.St.SetCaps(c)
	return c
}

func (e *Engine) resolveIface(name string) (netutil.LocalIface, error) {
	if name != "" {
		if l, ok := netutil.IfaceByName(name); ok {
			return l, nil
		}
		return netutil.LocalIface{}, fmt.Errorf("interface %q not found or has no IPv4 address", name)
	}
	if l, ok := netutil.DefaultIface(); ok {
		return l, nil
	}
	return netutil.LocalIface{}, errors.New("no usable network interface")
}

// StartMonitoring begins passive listening and Storm Guard on ifname
// ("" = default). It's idempotent per interface.
func (e *Engine) StartMonitoring(ifname string) error {
	local, err := e.resolveIface(ifname)
	if err != nil {
		return err
	}
	e.mu.Lock()
	if e.iface == local.Iface.Name && e.passive != nil {
		e.mu.Unlock()
		return nil
	}
	e.mu.Unlock()
	e.StopMonitoring()

	selfID := e.observeSelf(local)
	hub, herr := capture.Acquire(local.Iface.Name)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.iface, e.selfID = local.Iface.Name, selfID
	if herr == nil {
		e.hub = hub
		e.storm = storm.Start(e.St, hub, e.warnPPS, e.critPPS)
		e.St.Logf("monitor", "Raw capture active on %s: passive discovery and Storm Guard running", local.Iface.Name)
	} else {
		_, note := capture.Probe(local.Iface.Name)
		e.storm = storm.Unavailable(note)
		e.St.AddEvent(model.SevLow, "monitor", "Raw capture unavailable on "+local.Iface.Name+": "+note, "")
	}
	e.passive = passive.Start(e.St, e.hub, local, selfID)
	return nil
}

// StopMonitoring stops the passive listener and Storm Guard.
func (e *Engine) StopMonitoring() {
	e.mu.Lock()
	p, s, h := e.passive, e.storm, e.hub
	e.passive, e.storm, e.hub, e.iface = nil, nil, nil, ""
	e.mu.Unlock()
	if p != nil {
		p.Stop()
	}
	if s != nil {
		s.Stop()
	}
	capture.Release(h)
}

// PassiveStats for the dashboard.
func (e *Engine) PassiveStats() passive.Stats {
	e.mu.Lock()
	p := e.passive
	e.mu.Unlock()
	if p == nil {
		return passive.Stats{}
	}
	return p.Stats()
}

// StormStatus for the dashboard.
func (e *Engine) StormStatus() model.StormStatus {
	e.mu.Lock()
	s := e.storm
	e.mu.Unlock()
	if s == nil {
		return model.StormStatus{State: "off"}
	}
	return s.Status()
}

// StartNetFlow begins collecting on addr (default ":2055").
func (e *Engine) StartNetFlow(addr string) error {
	if addr == "" {
		addr = ":2055"
	}
	e.StopNetFlow()
	c, err := netflow.Start(e.St, addr)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.flow = c
	e.mu.Unlock()
	e.St.Logf("netflow", "NetFlow/IPFIX collector listening on UDP %s", addr)
	return nil
}

// StopNetFlow stops the collector.
func (e *Engine) StopNetFlow() {
	e.mu.Lock()
	c := e.flow
	e.flow = nil
	e.mu.Unlock()
	c.Stop()
}

// FlowSummary for the dashboard.
func (e *Engine) FlowSummary() model.FlowSummary {
	e.mu.Lock()
	c := e.flow
	e.mu.Unlock()
	return c.Summary()
}

func (e *Engine) observeSelf(local netutil.LocalIface) string {
	host, _ := os.Hostname()
	return e.St.Observe(local.Addr.String(), local.Iface.HardwareAddr.String(), model.SrcLocalHost, func(d *model.Device) {
		d.IsSelf = true
		store.AddName(d, host)
		d.Notes = "OctoLAN collector"
		d.OS.Family = map[string]string{"windows": "Windows", "darwin": "macOS", "linux": "Linux"}[runtime.GOOS]
		d.OS.Confidence = 100
		if d.Type == model.TypeUnknown {
			d.Type = model.TypeWorkstation
		}
	})
}

// ---- scan pipeline ----

var phaseNames = []string{"Prepare", "ARP sweep", "Ping sweep", "TCP discovery", "Service scan",
	"Name resolution", "SNMP polling", "Service discovery", "Passive listening", "Analysis"}

// Running reports whether a scan is in progress.
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cancel != nil
}

// StartScan runs a scan in the background.
func (e *Engine) StartScan(cfg model.ScanConfig) error {
	if len(cfg.Targets) > 0 {
		if _, err := netutil.ParseTargets(cfg.Targets); err != nil {
			return err
		}
	}
	if _, err := discovery.ParsePorts(cfg.Ports); err != nil {
		return err
	}
	if _, err := e.resolveIface(cfg.Interface); err != nil {
		return err
	}
	e.mu.Lock()
	if e.cancel != nil {
		e.mu.Unlock()
		return errors.New("a scan is already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.scanDone = make(chan struct{})
	done := e.scanDone
	e.mu.Unlock()
	go func() {
		defer close(done)
		_ = e.RunScan(ctx, cfg)
	}()
	return nil
}

// StopScan cancels a running scan and waits for it to wind down.
func (e *Engine) StopScan() {
	e.mu.Lock()
	c, done := e.cancel, e.scanDone
	e.mu.Unlock()
	if c != nil {
		c()
		if done != nil {
			<-done
		}
	}
}

type tracker struct {
	e     *Engine
	start time.Time
	cur   int
	t0    time.Time
}

func (t *tracker) begin(i int, detail string) {
	t.cur, t.t0 = i, time.Now()
	t.e.St.UpdateScan(func(s *model.ScanStatus) {
		s.Phase = phaseNames[i]
		s.Phases[i].State = "running"
		s.Phases[i].Detail = detail
		s.Progress = float64(i) / float64(len(phaseNames))
		s.Message = detail
	})
}

func (t *tracker) progress(frac float64, detail string) {
	t.e.St.UpdateScan(func(s *model.ScanStatus) {
		s.Progress = (float64(t.cur) + min(max(frac, 0), 1)) / float64(len(phaseNames))
		if detail != "" {
			s.Message = detail
			s.Phases[t.cur].Detail = detail
		}
	})
}

func (t *tracker) end(state, detail string) {
	t.e.St.UpdateScan(func(s *model.ScanStatus) {
		s.Phases[t.cur].State = state
		if detail != "" {
			s.Phases[t.cur].Detail = detail
		}
		s.Phases[t.cur].Duration = time.Since(t.t0).Milliseconds()
	})
}

func (t *tracker) skip(i int, why string) {
	t.e.St.UpdateScan(func(s *model.ScanStatus) {
		s.Phases[i].State = "skipped"
		s.Phases[i].Detail = why
	})
}

// RunScan executes the pipeline synchronously.
func (e *Engine) RunScan(ctx context.Context, cfg model.ScanConfig) (err error) {
	defer func() {
		e.mu.Lock()
		e.cancel = nil
		e.mu.Unlock()
		if r := recover(); r != nil {
			err = fmt.Errorf("scan crashed: %v", r)
			e.St.AddEvent(model.SevHigh, "scan", err.Error(), "")
		}
		if errors.Is(err, context.Canceled) {
			// Keep what was found: classify and score the partial results.
			e.Analyze()
			_, _ = e.AutoSave()
		}
		e.St.UpdateScan(func(s *model.ScanStatus) {
			s.Running = false
			s.Finished = time.Now()
			if err != nil && !errors.Is(err, context.Canceled) {
				s.Message = "Scan failed: " + err.Error()
			} else if errors.Is(err, context.Canceled) {
				s.Message = "Scan stopped"
			} else {
				s.Progress = 1
				s.Message = "Assessment complete"
			}
			for i := range s.Phases {
				if s.Phases[i].State == "running" || s.Phases[i].State == "pending" {
					s.Phases[i].State = "skipped"
				}
			}
		})
	}()

	if cfg.Rate <= 0 {
		cfg.Rate = 400
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 900 * time.Millisecond
	}
	if cfg.Site != "" {
		e.St.SetSite(cfg.Site)
	}
	phases := make([]model.PhaseStatus, len(phaseNames))
	for i, n := range phaseNames {
		phases[i] = model.PhaseStatus{Name: n, State: "pending"}
	}
	cfgCopy := cfg
	e.St.UpdateScan(func(s *model.ScanStatus) {
		*s = model.ScanStatus{Running: true, Started: time.Now(), Phases: phases, Config: &cfgCopy, Phase: "Prepare"}
	})
	t := &tracker{e: e, start: time.Now()}

	// ---- Prepare ----
	t.begin(0, "Resolving interface and targets")
	local, err := e.resolveIface(cfg.Interface)
	if err != nil {
		t.end("error", err.Error())
		return err
	}
	if err := e.StartMonitoring(local.Iface.Name); err != nil {
		e.St.AddEvent(model.SevLow, "scan", "monitoring: "+err.Error(), "")
	}
	gw, _ := netutil.DefaultGateway()
	scanPrefix := netutil.ScanPrefixFor(local)
	e.St.AddSubnet(model.Subnet{CIDR: local.Prefix.String(), Interface: local.Iface.Name, Local: true,
		Hosts: netutil.HostCount(local.Prefix), Gateway: gwIf(gw, local.Prefix)})
	if len(cfg.Targets) == 0 {
		cfg.Targets = []string{scanPrefix.String()}
		if scanPrefix != local.Prefix {
			e.St.AddEvent(model.SevInfo, "scan", fmt.Sprintf("Local subnet %s is large; scanning %s around this host (add targets to widen)", local.Prefix, scanPrefix), "")
		}
	}
	targets, err := netutil.ParseTargets(cfg.Targets)
	if err != nil {
		t.end("error", err.Error())
		return err
	}
	for _, spec := range cfg.Targets {
		if p, err := netip.ParsePrefix(strings.TrimSpace(spec)); err == nil && p.Masked() != local.Prefix {
			e.St.AddSubnet(model.Subnet{CIDR: p.Masked().String(), Hosts: netutil.HostCount(p)})
		}
	}
	if gw.IsValid() {
		e.St.Observe(gw.String(), "", "", func(d *model.Device) { d.IsGateway = true })
	}
	var localTargets, remoteTargets []netip.Addr
	for _, a := range targets {
		if local.Prefix.Contains(a) {
			localTargets = append(localTargets, a)
		} else {
			remoteTargets = append(remoteTargets, a)
		}
	}
	e.mu.Lock()
	hub := e.hub
	e.mu.Unlock()
	t.end("done", fmt.Sprintf("%s (%s) · %d targets (%d local, %d routed)", local.Iface.Name, local.Addr, len(targets), len(localTargets), len(remoteTargets)))
	e.St.Logf("scan", "Assessment started on %s: %d targets", local.Iface.Name, len(targets))

	alive := func() []netip.Addr {
		var out []netip.Addr
		set := map[netip.Addr]bool{}
		for _, a := range targets {
			set[a] = true
		}
		for _, d := range e.St.Devices() {
			if !d.Alive || d.IsSelf {
				continue
			}
			for _, s := range d.IPs {
				if a, err := netip.ParseAddr(s); err == nil && a.Is4() && (set[a] || d.IsGateway) {
					out = append(out, a)
				}
			}
		}
		slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
		return slices.Compact(out)
	}

	if cfg.ZeroFootprint {
		for i := 1; i <= 7; i++ {
			t.skip(i, "zero-footprint mode (passive only)")
		}
		e.harvestARPTable(local)
	} else {
		// ---- ARP sweep ----
		if cfg.SkipARP || len(localTargets) == 0 {
			t.skip(1, "no local targets")
		} else {
			t.begin(1, fmt.Sprintf("Layer-2 sweep of %d local addresses", len(localTargets)))
			n := 0
			var mu sync.Mutex
			onReply := func(r discovery.ARPResult) {
				mu.Lock()
				n++
				c := n
				mu.Unlock()
				e.St.Observe(r.IP.String(), r.MAC.String(), model.SrcARP, nil)
				if c%10 == 0 {
					t.progress(0.5, fmt.Sprintf("%d hosts answered ARP", c))
				}
			}
			method := ""
			switch {
			case hub != nil:
				method = "raw ARP frames"
				if err := discovery.ARPSweep(ctx, hub, local, localTargets, cfg.Rate, 1500*time.Millisecond, onReply); err != nil && ctx.Err() == nil {
					e.St.AddEvent(model.SevLow, "arp", "ARP sweep: "+err.Error(), "")
				}
			case runtime.GOOS == "windows":
				method = "Windows SendARP API"
				discovery.WindowsARP(ctx, local, localTargets, onReply)
			default:
				method = "OS ARP cache (unprivileged)"
				discovery.PrimeARP(ctx, local, localTargets, cfg.Rate)
				sleepCtx(ctx, 2*time.Second)
			}
			e.harvestARPTable(local)
			t.end("done", fmt.Sprintf("%d hosts via %s", n, method))
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// ---- Ping sweep ----
		t.begin(2, fmt.Sprintf("ICMP echo to %d addresses", len(targets)))
		pinged := 0
		var pmu sync.Mutex
		mode, perr := discovery.PingSweep(ctx, targets, cfg.Rate, cfg.Timeout, func(r discovery.PingResult) {
			pmu.Lock()
			pinged++
			c := pinged
			pmu.Unlock()
			e.St.Observe(r.IP.String(), "", model.SrcICMP, func(d *model.Device) {
				us := r.RTT.Microseconds()
				if us <= 0 {
					us = 1
				}
				if d.RTTMicro == 0 || us < d.RTTMicro {
					d.RTTMicro = us
				}
				if r.TTL > 0 {
					d.TTL = r.TTL
				}
			})
			if c%10 == 0 {
				t.progress(0.5, fmt.Sprintf("%d hosts replied to ping", c))
			}
		})
		if perr != nil && !errors.Is(perr, context.Canceled) {
			t.end("skipped", "ICMP unavailable ("+mode+"): falling back to TCP discovery")
		} else {
			t.end("done", fmt.Sprintf("%d replies (%s ICMP)", pinged, mode))
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		e.harvestARPTable(local)

		// ---- TCP discovery for silent hosts ----
		silent := []netip.Addr{}
		up := map[netip.Addr]bool{}
		for _, a := range alive() {
			up[a] = true
		}
		for _, a := range targets {
			// Local hosts were already covered by ARP when possible.
			if !up[a] && a != local.Addr && (!local.Prefix.Contains(a) || (hub == nil && runtime.GOOS != "windows")) {
				silent = append(silent, a)
			}
		}
		if len(silent) == 0 {
			t.skip(3, "every target already accounted for")
		} else {
			t.begin(3, fmt.Sprintf("TCP ping of %d silent addresses", len(silent)))
			found := 0
			discovery.TCPPing(ctx, silent, 512, 700*time.Millisecond, func(ip netip.Addr, port int) {
				found++
				e.St.Observe(ip.String(), "", model.SrcTCP, func(d *model.Device) {
					if port > 0 {
						addPort(d, model.Port{Port: port, Proto: "tcp", Service: discovery.ServiceNames[port]})
					}
				})
			})
			t.end("done", fmt.Sprintf("%d additional hosts found", found))
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// ---- Service scan ----
		hosts := alive()
		ports, perr2 := discovery.ParsePorts(cfg.Ports)
		if cfg.SkipPorts || perr2 != nil || len(ports) == 0 || len(hosts) == 0 {
			why := "disabled"
			if perr2 != nil {
				why = perr2.Error()
			}
			t.skip(4, why)
		} else {
			t.begin(4, fmt.Sprintf("%d ports × %d hosts", len(ports), len(hosts)))
			e.serviceScan(ctx, t, hub, hosts, ports, cfg.Timeout)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// ---- Names ----
		hosts = alive()
		t.begin(5, fmt.Sprintf("Reverse DNS, NetBIOS and mDNS for %d hosts", len(hosts)))
		e.resolveNames(ctx, t, hosts)
		t.end("done", "")
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// ---- SNMP ----
		if cfg.SkipSNMP {
			t.skip(6, "disabled")
		} else {
			comms := cfg.Communities
			if len(comms) == 0 {
				comms = discovery.DefaultCommunities
			}
			creds := discovery.SNMPCreds{Communities: comms, V3: cfg.SNMPv3}
			t.begin(6, fmt.Sprintf("Polling %d hosts with %d credential set(s)", len(hosts), len(comms)+len(cfg.SNMPv3)))
			n := e.snmpCrawl(ctx, t, hosts, creds, cfg.Timeout)
			t.end("done", fmt.Sprintf("%d SNMP agents polled", n))
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// ---- mDNS / SSDP ----
		t.begin(7, "Querying mDNS/Bonjour and SSDP/UPnP")
		passive.ActiveServiceDiscovery(ctx, e.St, local, 4*time.Second)
		e.enrichUPnP(ctx)
		t.end("done", "")
	}

	// ---- Passive listening for the remaining window ----
	if cfg.PassiveSeconds > 0 {
		remain := time.Duration(cfg.PassiveSeconds)*time.Second - time.Since(t.start)
		if remain > 0 {
			t.begin(8, fmt.Sprintf("Listening passively for %s more", remain.Round(time.Second)))
			end := time.Now().Add(remain)
			for time.Now().Before(end) && ctx.Err() == nil {
				sleepCtx(ctx, time.Second)
				t.progress(1-time.Until(end).Seconds()/remain.Seconds(), fmt.Sprintf("Listening… %s left", time.Until(end).Round(time.Second)))
			}
			t.end("done", "")
		} else {
			t.skip(8, "listening window already elapsed during active scan")
		}
	} else {
		t.skip(8, "passive window not requested (monitoring continues in the background)")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// ---- Analysis ----
	t.begin(9, "Classifying devices, building topology, scoring posture")
	e.Analyze()
	path, serr := e.AutoSave()
	if serr != nil {
		e.St.AddEvent(model.SevLow, "scan", "Could not save session: "+serr.Error(), "")
	}
	finds, score, grade := e.St.Findings()
	t.end("done", fmt.Sprintf("Score %d (%s), %d findings", score, grade, len(finds)))
	e.St.Logf("scan", "Assessment complete: %d devices, score %d (%s). Saved to %s", len(e.St.Devices()), score, grade, path)
	return nil
}

func gwIf(gw netip.Addr, p netip.Prefix) string {
	if gw.IsValid() && p.Contains(gw) {
		return gw.String()
	}
	return ""
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func addPort(d *model.Device, p model.Port) {
	for i, x := range d.Ports {
		if x.Port == p.Port && x.Proto == p.Proto {
			if p.Banner != "" {
				d.Ports[i].Banner = p.Banner
			}
			return
		}
	}
	d.Ports = append(d.Ports, p)
	slices.SortFunc(d.Ports, func(a, b model.Port) int { return a.Port - b.Port })
}

func (e *Engine) harvestARPTable(local netutil.LocalIface) {
	entries, err := netutil.ARPTable()
	if err != nil {
		return
	}
	for _, en := range entries {
		if local.Prefix.Contains(en.IP) {
			e.St.Observe(en.IP.String(), en.MAC.String(), model.SrcARPTable, nil)
		}
	}
}

func (e *Engine) serviceScan(ctx context.Context, t *tracker, hub *capture.Hub, hosts []netip.Addr, ports []int, timeout time.Duration) {
	var sniffer *discovery.SynAckSniffer
	if hub != nil {
		sniffer = discovery.StartSynAckSniffer(hub)
	}
	total := len(hosts) * len(ports)
	var mu sync.Mutex
	var done atomic.Int64
	open := map[netip.Addr][]int{}
	tick := time.NewTicker(time.Second)
	stopTick := make(chan struct{})
	go func() {
		for {
			select {
			case <-tick.C:
				mu.Lock()
				n := 0
				for _, p := range open {
					n += len(p)
				}
				mu.Unlock()
				t.progress(0.4*float64(done.Load())/float64(max(total, 1)), fmt.Sprintf("%d open ports found (%d/%d probes)", n, done.Load(), total))
			case <-stopTick:
				tick.Stop()
				return
			}
		}
	}()
	discovery.ConnectScan(ctx, hosts, ports, 384, min(timeout, 1200*time.Millisecond), &done, func(h discovery.PortHit) {
		mu.Lock()
		open[h.IP] = append(open[h.IP], h.Port)
		mu.Unlock()
		e.St.Observe(h.IP.String(), "", model.SrcTCP, func(d *model.Device) {
			addPort(d, model.Port{Port: h.Port, Proto: "tcp", Service: discovery.ServiceNames[h.Port]})
		})
	})
	close(stopTick)
	traits := sniffer.Stop()
	for ip, tr := range traits {
		if id := e.St.FindByIP(ip.String()); id != "" {
			e.St.Update(id, func(d *model.Device) {
				d.OS.InitialTTL = discovery.NormTTL(tr.TTL)
				d.OS.Window, d.OS.DF, d.OS.MSS = tr.Window, tr.DF, tr.MSS
				if d.TTL == 0 {
					d.TTL = tr.TTL
				}
			})
		}
	}

	// Deep probes: banners, TLS certificates, SMB/NTLM.
	t.progress(0.4, "Grabbing banners, certificates and SMB details")
	type job struct {
		ip    netip.Addr
		ports []int
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	var probed int
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				e.probeHost(ctx, j.ip, j.ports, timeout)
				mu.Lock()
				probed++
				p := probed
				mu.Unlock()
				t.progress(0.4+0.6*float64(p)/float64(max(len(open), 1)), fmt.Sprintf("Probed services on %d/%d hosts", p, len(open)))
			}
		}()
	}
	for ip, ps := range open {
		if ctx.Err() != nil {
			break
		}
		jobs <- job{ip, ps}
	}
	close(jobs)
	wg.Wait()
	n := 0
	for _, p := range open {
		n += len(p)
	}
	t.end("done", fmt.Sprintf("%d open ports on %d hosts", n, len(open)))
}

func (e *Engine) probeHost(ctx context.Context, ip netip.Addr, ports []int, timeout time.Duration) {
	id := e.St.FindByIP(ip.String())
	if id == "" {
		return
	}
	for _, p := range ports {
		if ctx.Err() != nil {
			return
		}
		if b := discovery.GrabBanner(ctx, ip, p, timeout); b != "" {
			e.St.Update(id, func(d *model.Device) { addPort(d, model.Port{Port: p, Proto: "tcp", Banner: b}) })
		}
		if discovery.IsTLSPort(p) {
			if info := discovery.ProbeTLS(ctx, ip, p, timeout); info != nil {
				e.St.Update(id, func(d *model.Device) {
					d.TLS = slices.DeleteFunc(d.TLS, func(x model.TLSInfo) bool { return x.Port == p })
					d.TLS = append(d.TLS, *info)
				})
			}
		}
		if p == 445 {
			if smb := discovery.ProbeSMB(ctx, ip, timeout); smb != nil {
				e.St.Update(id, func(d *model.Device) {
					d.SMB = smb
					if smb.NetBIOSName != "" {
						store.AddName(d, smb.NetBIOSName)
					}
					if smb.DNSName != "" {
						store.AddName(d, smb.DNSName)
					}
					if smb.DNSDomain != "" {
						d.Domain = smb.DNSDomain
					} else if smb.NetBIOSDom != "" {
						d.Domain = smb.NetBIOSDom
					}
					store.AddSource(d, model.SrcSMB)
				})
			}
		}
	}
}

func (e *Engine) resolveNames(ctx context.Context, t *tracker, hosts []netip.Addr) {
	work := make(chan netip.Addr)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range work {
				id := e.St.FindByIP(ip.String())
				if id == "" {
					continue
				}
				names := discovery.ReverseDNS(ctx, ip, 2*time.Second)
				nb := discovery.NetBIOSStatus(ctx, ip, 1200*time.Millisecond)
				var mdns string
				if len(names) == 0 && nb == nil {
					mdns = discovery.MDNSReverse(ctx, ip, 1200*time.Millisecond)
				}
				e.St.Update(id, func(d *model.Device) {
					for _, n := range names {
						store.AddName(d, n)
						store.AddSource(d, model.SrcDNS)
					}
					if nb != nil {
						store.AddName(d, nb.Name)
						store.AddSource(d, model.SrcNetBIOS)
						if d.Domain == "" {
							d.Domain = nb.Workgroup
						}
						if nb.IsDC {
							d.Notes = joinNote(d.Notes, "Domain controller (NetBIOS)")
							d.Type = model.TypeServer
						}
						if d.MAC == "" && nb.MAC != nil {
							d.Notes = joinNote(d.Notes, "NetBIOS MAC "+nb.MAC.String())
						}
					}
					if mdns != "" {
						store.AddName(d, mdns)
						store.AddSource(d, model.SrcMDNS)
					}
				})
				mu.Lock()
				done++
				t.progress(float64(done)/float64(max(len(hosts), 1)), fmt.Sprintf("Named %d/%d hosts", done, len(hosts)))
				mu.Unlock()
			}
		}()
	}
	for _, h := range hosts {
		if ctx.Err() != nil {
			break
		}
		work <- h
	}
	close(work)
	wg.Wait()
}

func joinNote(n, s string) string {
	if strings.Contains(n, s) {
		return n
	}
	if n == "" {
		return s
	}
	return n + "; " + s
}

// snmpCrawl polls every host, then follows LLDP/CDP management addresses
// to reach infrastructure that wasn't in the target list.
func (e *Engine) snmpCrawl(ctx context.Context, t *tracker, hosts []netip.Addr, creds discovery.SNMPCreds, timeout time.Duration) int {
	timeout = min(max(timeout, 800*time.Millisecond), 2*time.Second)
	queued := map[netip.Addr]bool{}
	queue := slices.Clone(hosts)
	for _, h := range hosts {
		queued[h] = true
	}
	polled := 0
	const maxExtra = 256
	extra := 0
	for len(queue) > 0 && ctx.Err() == nil {
		batch := queue
		queue = nil
		var mu sync.Mutex
		var newIPs []netip.Addr
		work := make(chan netip.Addr)
		var wg sync.WaitGroup
		done := 0
		for range 48 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ip := range work {
					found := e.pollOne(ctx, ip, creds, timeout)
					mu.Lock()
					done++
					if found != nil {
						polled++
						newIPs = append(newIPs, found...)
					}
					t.progress(float64(done)/float64(len(batch)), fmt.Sprintf("SNMP: %d agents answered (%d/%d probed)", polled, done, len(batch)))
					mu.Unlock()
				}
			}()
		}
		for _, ip := range batch {
			if ctx.Err() != nil {
				break
			}
			work <- ip
		}
		close(work)
		wg.Wait()
		for _, ip := range newIPs {
			if !queued[ip] && extra < maxExtra && ip.Is4() && !ip.IsLoopback() {
				queued[ip] = true
				queue = append(queue, ip)
				extra++
			}
		}
		if len(queue) > 0 {
			e.St.Logf("snmp", "Following %d LLDP/CDP neighbour management addresses", len(queue))
		}
	}
	return polled
}

// pollOne returns neighbour management IPs when the agent answered, nil
// otherwise.
func (e *Engine) pollOne(ctx context.Context, ip netip.Addr, creds discovery.SNMPCreds, timeout time.Duration) []netip.Addr {
	g, info := discovery.SNMPConnect(ctx, ip, creds, timeout)
	if g == nil {
		return nil
	}
	defer g.Conn.Close()
	res := discovery.SNMPPoll(ctx, g, info)

	// Prefer the chassis MAC (first physical interface MAC) as identity.
	mac := ""
	if id := e.St.FindByIP(ip.String()); id != "" {
		if d := e.St.Get(id); d != nil {
			mac = d.MAC
		}
	}
	id := e.St.Observe(ip.String(), mac, model.SrcSNMP, func(d *model.Device) {
		inf := res.Info
		d.SNMP = &inf
		if inf.SysName != "" {
			store.AddName(d, inf.SysName)
		}
		d.Location, d.Contact = res.Location, res.Contact
		d.Interfaces = res.Interfaces
		d.Neighbors = mergeNeighbors(d.Neighbors, res.Neighbors)
		d.FDB = res.FDB
		d.VLANs = res.VLANs
		if res.Model != "" {
			d.Model = res.Model
		}
		if res.Serial != "" {
			d.Serial = res.Serial
		}
		if res.Firmware != "" {
			d.Firmware = res.Firmware
		}
		if res.Extra != "" {
			d.Notes = joinNote(d.Notes, res.Extra)
		}
		for _, oip := range res.OwnIPs {
			if !slices.Contains(d.IPs, oip) && oip != "0.0.0.0" {
				d.IPs = append(d.IPs, oip)
			}
		}
	})
	if inf := res.Info; inf.DefaultComm {
		e.St.AddEvent(model.SevHigh, "snmp", fmt.Sprintf("%s (%s) answers SNMP community %q", ip, inf.SysName, inf.Community), id)
	}
	for _, v := range res.VLANs {
		e.St.ObserveVLAN(model.VLAN{ID: v.ID, Name: v.Name, Source: "snmp"})
	}
	// Hosts in the router's ARP cache, including other VLANs/subnets.
	for _, a := range res.ARP {
		if a.IP.IsLoopback() || a.IP.IsUnspecified() {
			continue
		}
		e.St.Observe(a.IP.String(), a.MAC.String(), model.SrcSNMP+"-arp", nil)
	}
	var next []netip.Addr
	for _, n := range res.Neighbors {
		if a, err := netip.ParseAddr(n.RemoteIP); err == nil {
			next = append(next, a)
		}
	}
	if next == nil {
		next = []netip.Addr{}
	}
	return next
}

func mergeNeighbors(old, fresh []model.Neighbor) []model.Neighbor {
	out := slices.Clone(fresh)
	for _, o := range old {
		if !slices.ContainsFunc(out, func(n model.Neighbor) bool {
			return n.Protocol == o.Protocol && n.LocalPort == o.LocalPort && n.RemoteChassis == o.RemoteChassis
		}) {
			out = append(out, o)
		}
	}
	return out
}

func (e *Engine) enrichUPnP(ctx context.Context) {
	n := 0
	for _, d := range e.St.Devices() {
		for _, s := range d.Services {
			if s.Type != "upnp-location" || n >= 50 {
				continue
			}
			n++
			friendly, mfr, modelName := passive.FetchUPnPDescription(ctx, s.Name)
			if friendly == "" && modelName == "" {
				continue
			}
			e.St.Update(d.ID, func(dd *model.Device) {
				if friendly != "" {
					dd.Notes = joinNote(dd.Notes, "UPnP: "+friendly)
				}
				if dd.Model == "" && modelName != "" {
					dd.Model = strings.TrimSpace(mfr + " " + modelName)
				}
			})
			break
		}
	}
}

// Analyze classifies devices, rebuilds the topology and re-scores.
func (e *Engine) Analyze() {
	for _, d := range e.St.Devices() {
		e.St.Update(d.ID, discovery.Classify)
	}
	devs := e.St.Devices()
	e.St.SetLinks(topology.Build(devs, e.St.Subnets()))
	finds, score, grade := assess.Run(assess.Input{
		Devices: devs, DHCPServers: e.St.DHCPServers(), DuplicateIP: e.St.DuplicateIPs(),
		Storm: e.StormStatus(), Flows: e.FlowSummary(), VLANs: e.St.VLANs(),
	})
	e.St.SetFindings(finds, score, grade)
}

// SessionDir is where this site's files are written.
func (e *Engine) SessionDir() string {
	site := sanitize(e.St.Site())
	if site == "" {
		site = "site"
	}
	return filepath.Join(e.DataDir, site)
}

// AutoSave writes the session snapshot and returns its path.
func (e *Engine) AutoSave() (string, error) {
	dir := e.SessionDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "session-"+time.Now().Format("20060102-150405")+".json")
	return path, e.St.Save(path, e.Version)
}

func sanitize(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ' || r == '.':
			b.WriteRune('-')
		}
	}
	return b.String()
}

// LocalAddrs lists this machine's IPv4 addresses (used by the web server
// to tell the user where to browse).
func LocalAddrs() []string {
	var out []string
	for _, l := range netutil.LocalIPv4() {
		out = append(out, l.Addr.String())
	}
	return out
}
