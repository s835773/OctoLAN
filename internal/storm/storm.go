// Package storm is Storm Guard: a promiscuous packets-per-second meter
// that detects broadcast storms and layer-2 loops, and watches Spanning
// Tree BPDUs for root-bridge changes and topology-change floods.
package storm

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/s835773/OctoLAN/internal/capture"
	"github.com/s835773/OctoLAN/internal/model"
	"github.com/s835773/OctoLAN/internal/oui"
	"github.com/s835773/OctoLAN/internal/store"
)

const seriesLen = 300 // five minutes of 1-second samples

// Guard runs until Stop.
type Guard struct {
	st    *store.Store
	iface string
	warn  int
	crit  int

	mu       sync.Mutex
	cur      model.PPSSample
	series   []model.PPSSample
	peak     model.PPSSample
	bcastBy  map[string]uint64 // src MAC -> broadcast frames (rolling)
	dupHash  map[uint64]uint8
	stp      model.STPInfo
	lastTCAt time.Time
	state    string
	err      string
	running  bool

	stop func()
	done chan struct{}
}

// Start begins metering on hub. warn/crit are broadcast+multicast PPS
// thresholds (0 = defaults of 1000 / 5000).
func Start(st *store.Store, hub *capture.Hub, warn, crit int) *Guard {
	if warn <= 0 {
		warn = 1000
	}
	if crit <= 0 {
		crit = 5000
	}
	g := &Guard{st: st, iface: hub.Iface.Name, warn: warn, crit: crit, state: "ok",
		bcastBy: map[string]uint64{}, dupHash: map[uint64]uint8{}, running: true, done: make(chan struct{})}
	ch, unsub := hub.Subscribe("storm", 65536)
	g.stop = unsub
	go g.run(ch)
	return g
}

// Unavailable returns a Guard that only reports why it can't run.
func Unavailable(reason string) *Guard {
	return &Guard{err: reason, state: "unavailable"}
}

// Stop ends metering.
func (g *Guard) Stop() {
	if g == nil || g.stop == nil {
		return
	}
	g.stop()
	<-g.done
	g.mu.Lock()
	g.running = false
	g.mu.Unlock()
}

func (g *Guard) run(ch <-chan capture.Packet) {
	defer close(g.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	decay := time.NewTicker(60 * time.Second)
	defer decay.Stop()
	for {
		select {
		case p, ok := <-ch:
			if !ok {
				return
			}
			g.account(p.Data)
		case <-tick.C:
			g.roll()
		case <-decay.C:
			g.mu.Lock()
			for k, v := range g.bcastBy {
				if v/2 == 0 {
					delete(g.bcastBy, k)
				} else {
					g.bcastBy[k] = v / 2
				}
			}
			g.mu.Unlock()
		}
	}
}

func (g *Guard) account(f []byte) {
	if len(f) < 14 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	c := &g.cur
	c.Total++
	c.Bytes += len(f)
	dst := f[0:6]
	isBcast := dst[0] == 0xff && dst[1] == 0xff && dst[2] == 0xff && dst[3] == 0xff && dst[4] == 0xff && dst[5] == 0xff
	switch {
	case isBcast:
		c.Broadcast++
	case dst[0]&1 == 1:
		c.Multicast++
	default:
		c.Unicast++
	}
	et := binary.BigEndian.Uint16(f[12:14])
	off := 14
	if et == 0x8100 && len(f) >= 18 {
		et = binary.BigEndian.Uint16(f[16:18])
		off = 18
	}
	if et == 0x0806 {
		c.ARP++
	}
	if isBcast || dst[0]&1 == 1 {
		g.bcastBy[net.HardwareAddr(f[6:12]).String()]++
		// The same broadcast frame arriving repeatedly within one second
		// is the signature of a bridging loop.
		h := fnv(f)
		if n := g.dupHash[h]; n < 255 {
			g.dupHash[h] = n + 1
			if n >= 2 {
				c.Dups++
			}
		}
	}
	// STP BPDUs: 802.3 length field + LLC 42 42 03.
	if et <= 1500 && len(f) >= off+3 && f[off] == 0x42 && f[off+1] == 0x42 {
		g.bpdu(f[off+3:], net.HardwareAddr(f[6:12]))
	}
}

func fnv(b []byte) uint64 {
	var h uint64 = 14695981039346656037
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

func bridgeID(b []byte) (string, int) {
	prio := int(binary.BigEndian.Uint16(b[0:2]))
	return fmt.Sprintf("%d.%s", prio, net.HardwareAddr(b[2:8])), prio &^ 0x0fff
}

func (g *Guard) bpdu(b []byte, src net.HardwareAddr) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 {
		return
	}
	s := &g.stp
	s.Seen = true
	s.BPDUs++
	ver, typ := b[2], b[3]
	switch ver {
	case 0:
		s.Protocol = "STP (802.1D)"
	case 2:
		s.Protocol = "RSTP (802.1w)"
	case 3:
		s.Protocol = "MSTP (802.1s)"
	}
	if typ == 0x80 { // TCN
		g.noteTC()
		return
	}
	if len(b) < 35 {
		return
	}
	flags := b[4]
	root, prio := bridgeID(b[5:13])
	cost := int(binary.BigEndian.Uint32(b[13:17]))
	sender, _ := bridgeID(b[17:25])
	if s.RootBridge != "" && s.RootBridge != root {
		s.RootChanges++
		prev := s.RootBridge
		go g.st.AddEvent(model.SevHigh, "stp", fmt.Sprintf("Spanning-tree root bridge changed from %s to %s", prev, root), "")
	} else if s.RootBridge == "" {
		vendor := oui.Lookup(net.HardwareAddr(b[7:13]))
		go g.st.AddEvent(model.SevInfo, "stp", fmt.Sprintf("%s root bridge is %s (%s), path cost %d", s.Protocol, root, vendor, cost), "")
	}
	s.RootBridge, s.RootPriority, s.RootCost, s.SenderBridge = root, prio, cost, sender
	if flags&0x01 != 0 {
		g.noteTC()
	}
}

func (g *Guard) noteTC() {
	now := time.Now()
	// A TC flag stays set for ~35s; count distinct events.
	if now.Sub(g.lastTCAt) > 40*time.Second {
		g.stp.TopologyChanges++
		g.stp.LastTC = now
		n := g.stp.TopologyChanges
		go g.st.AddEvent(model.SevMedium, "stp", fmt.Sprintf("Spanning-tree topology change #%d (a port went up/down or a loop is re-converging)", n), "")
	}
	g.lastTCAt = now
}

func (g *Guard) roll() {
	g.mu.Lock()
	c := g.cur
	c.T = time.Now().UnixMilli()
	g.series = append(g.series, c)
	if len(g.series) > seriesLen {
		g.series = g.series[len(g.series)-seriesLen:]
	}
	if c.Broadcast+c.Multicast > g.peak.Broadcast+g.peak.Multicast {
		g.peak = c
	}
	g.cur = model.PPSSample{}
	clear(g.dupHash)
	prev := g.state
	bm := c.Broadcast + c.Multicast
	switch {
	case bm >= g.crit || c.Dups >= 200:
		g.state = "storm"
	case bm >= g.warn || c.Dups >= 20:
		g.state = "warning"
	default:
		g.state = "ok"
	}
	state := g.state
	g.mu.Unlock()

	g.st.Publish("storm", g.Status())
	if state != prev {
		sev := model.SevInfo
		msg := fmt.Sprintf("Broadcast levels back to normal (%d bcast+mcast pps)", bm)
		switch state {
		case "warning":
			sev, msg = model.SevMedium, fmt.Sprintf("Elevated broadcast/multicast: %d pps (warn ≥ %d), %d repeated frames", bm, g.warn, c.Dups)
		case "storm":
			sev, msg = model.SevCritical, fmt.Sprintf("BROADCAST STORM: %d pps (critical ≥ %d), %d repeated frames/sec: check for a switching loop", bm, g.crit, c.Dups)
		}
		g.st.AddEvent(sev, "storm", msg, "")
	}
}

// Status is a snapshot for the dashboard and report.
func (g *Guard) Status() model.StormStatus {
	if g == nil {
		return model.StormStatus{State: "off"}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s := model.StormStatus{
		Running: g.running, Interface: g.iface, Error: g.err, State: g.state,
		Series: append([]model.PPSSample(nil), g.series...), Peak: g.peak, STP: g.stp,
		WarnPPS: g.warn, CritPPS: g.crit,
	}
	if n := len(g.series); n > 0 {
		s.Current = g.series[n-1]
		dups, total := 0, 0
		for _, x := range g.series {
			dups += x.Dups
			total += x.Broadcast + x.Multicast
		}
		if total > 0 {
			s.DuplicateRate = float64(dups) / float64(total)
		}
	}
	type kv struct {
		k string
		v uint64
	}
	var top []kv
	for k, v := range g.bcastBy {
		top = append(top, kv{k, v})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].v > top[j].v })
	for i := 0; i < len(top) && i < 10; i++ {
		label := oui.LookupString(top[i].k)
		s.TopBroadcaster = append(s.TopBroadcaster, model.Talker{Key: top[i].k, Label: label, Packets: top[i].v})
	}
	return s
}
