// Package topology turns the inventory into a layer-2/3 map: LLDP/CDP
// adjacencies first, then switch forwarding tables (which edge port each
// MAC lives on), then the collector's own uplink, and finally subnet
// "clouds" for devices we can't place more precisely.
package topology

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/s835773/OctoLAN/internal/model"
)

// uplinkMACThreshold: a switch port with more MACs than this is treated as
// an uplink/trunk rather than an edge port.
const uplinkMACThreshold = 6

// Build computes links for the given devices and subnets.
func Build(devs []*model.Device, subnets []model.Subnet) []model.Link {
	byID := map[string]*model.Device{}
	byMAC := map[string]string{}
	byIP := map[string]string{}
	byName := map[string]string{}
	for _, d := range devs {
		byID[d.ID] = d
		if d.MAC != "" {
			byMAC[d.MAC] = d.ID
		}
		for _, ip := range d.IPs {
			byIP[ip] = d.ID
		}
		for _, n := range append([]string{d.Hostname}, d.Names...) {
			if n != "" {
				byName[normName(n)] = d.ID
			}
		}
		if d.SNMP != nil && d.SNMP.SysName != "" {
			byName[normName(d.SNMP.SysName)] = d.ID
		}
		for _, ifc := range d.Interfaces {
			if ifc.MAC != "" {
				if _, taken := byMAC[ifc.MAC]; !taken {
					byMAC[ifc.MAC] = d.ID
				}
			}
		}
	}

	links := map[[2]string]*model.Link{}
	addLink := func(a, b, ap, bp, kind string, weight int) {
		if a == "" || b == "" || a == b {
			return
		}
		k := [2]string{a, b}
		if b < a {
			k = [2]string{b, a}
			ap, bp = bp, ap
		}
		if cur, ok := links[k]; ok {
			if weight > cur.Weight {
				cur.Kind, cur.Weight = kind, weight
			}
			if cur.APort == "" {
				cur.APort = ap
			}
			if cur.BPort == "" {
				cur.BPort = bp
			}
			return
		}
		links[k] = &model.Link{A: k[0], B: k[1], APort: ap, BPort: bp, Kind: kind, Weight: weight}
	}

	resolve := func(n model.Neighbor) string {
		if n.RemoteChassis != "" {
			if id, ok := byMAC[strings.ToLower(n.RemoteChassis)]; ok {
				return id
			}
		}
		if n.RemoteIP != "" {
			if id, ok := byIP[n.RemoteIP]; ok {
				return id
			}
		}
		if n.RemoteName != "" {
			if id, ok := byName[normName(n.RemoteName)]; ok {
				return id
			}
		}
		return ""
	}

	// 1. LLDP / CDP adjacencies (strongest evidence).
	uplinkPorts := map[string]map[string]bool{} // device -> ports with a neighbour
	for _, d := range devs {
		for _, n := range d.Neighbors {
			rid := resolve(n)
			if rid == "" {
				continue
			}
			addLink(d.ID, rid, n.LocalPort, n.RemotePort, n.Protocol, 3)
			if uplinkPorts[d.ID] == nil {
				uplinkPorts[d.ID] = map[string]bool{}
			}
			uplinkPorts[d.ID][n.LocalPort] = true
			if r := byID[rid]; r != nil && isInfra(r) {
				if uplinkPorts[rid] == nil {
					uplinkPorts[rid] = map[string]bool{}
				}
				uplinkPorts[rid][n.RemotePort] = true
			}
		}
	}

	// 2. Forwarding tables: place each MAC on the switch edge port with the
	// fewest MACs (the port it's physically closest to).
	type placement struct {
		sw, port string
		macs     int
	}
	best := map[string]placement{}
	for _, d := range devs {
		if len(d.FDB) == 0 {
			continue
		}
		perPort := map[string]int{}
		for _, e := range d.FDB {
			perPort[e.Port]++
		}
		for _, e := range d.FDB {
			if uplinkPorts[d.ID][e.Port] || perPort[e.Port] > uplinkMACThreshold {
				continue
			}
			tid, ok := byMAC[e.MAC]
			if !ok || tid == d.ID {
				continue
			}
			p := placement{sw: d.ID, port: e.Port, macs: perPort[e.Port]}
			if cur, ok := best[tid]; !ok || p.macs < cur.macs {
				best[tid] = p
			}
		}
		// Switch-to-switch links inferred from uplinks: a port that holds the
		// MAC of another switch is the path towards it.
		for _, e := range d.FDB {
			tid, ok := byMAC[e.MAC]
			if !ok || tid == d.ID || !isInfra(byID[tid]) {
				continue
			}
			k := [2]string{d.ID, tid}
			if tid < d.ID {
				k = [2]string{tid, d.ID}
			}
			if _, exists := links[k]; !exists && perPort[e.Port] > uplinkMACThreshold {
				// Only link if no better path is known; weight 1 so LLDP wins.
				addLink(d.ID, tid, e.Port, "", "fdb", 1)
			}
		}
	}
	for tid, p := range best {
		addLink(p.sw, tid, p.port, "", "fdb", 2)
	}

	// 3. Subnet clouds: anything still unattached hangs off its subnet,
	// which hangs off the gateway.
	linked := map[string]bool{}
	for k := range links {
		linked[k[0]], linked[k[1]] = true, true
	}
	type sn struct {
		p  netip.Prefix
		gw string
	}
	var nets []sn
	for _, s := range subnets {
		p, err := netip.ParsePrefix(s.CIDR)
		if err != nil {
			continue
		}
		gw := ""
		if s.Gateway != "" {
			gw = byIP[s.Gateway]
		}
		nets = append(nets, sn{p, gw})
	}
	sort.Slice(nets, func(i, j int) bool { return nets[i].p.Bits() > nets[j].p.Bits() })
	cloudFor := func(d *model.Device) (string, string) {
		for _, ipS := range d.IPs {
			ip, err := netip.ParseAddr(ipS)
			if err != nil {
				continue
			}
			for _, n := range nets {
				if n.p.Contains(ip) {
					return "net:" + n.p.String(), n.gw
				}
			}
		}
		return "net:other", ""
	}
	// The core of each subnet: the gateway if known, else the most
	// connected switch already in the graph.
	usedClouds := map[string]string{}
	for _, d := range devs {
		if linked[d.ID] {
			continue
		}
		cloud, gw := cloudFor(d)
		if d.ID == gw {
			continue
		}
		addLink(cloud, d.ID, "", "", "inferred", 0)
		usedClouds[cloud] = gw
	}
	for cloud, gw := range usedClouds {
		if gw == "" {
			gw = coreSwitch(devs, links)
		}
		if gw != "" {
			addLink(gw, cloud, "", "", "gateway", 0)
		}
	}
	// Connect the gateway to the collector's subnet if nothing links it.
	for _, n := range nets {
		if n.gw != "" && !linked[n.gw] {
			if _, used := usedClouds["net:"+n.p.String()]; !used {
				if core := coreSwitch(devs, links); core != "" && core != n.gw {
					addLink(core, n.gw, "", "", "inferred", 0)
				}
			}
		}
	}

	out := make([]model.Link, 0, len(links))
	for _, l := range links {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].A != out[j].A {
			return out[i].A < out[j].A
		}
		return out[i].B < out[j].B
	})
	return out
}

func isInfra(d *model.Device) bool {
	if d == nil {
		return false
	}
	switch d.Type {
	case model.TypeSwitch, model.TypeRouter, model.TypeFirewall, model.TypeAccessPoint:
		return true
	}
	return false
}

func coreSwitch(devs []*model.Device, links map[[2]string]*model.Link) string {
	deg := map[string]int{}
	for k := range links {
		deg[k[0]]++
		deg[k[1]]++
	}
	best, bestDeg := "", -1
	for _, d := range devs {
		if d.Type == model.TypeSwitch && deg[d.ID] > bestDeg {
			best, bestDeg = d.ID, deg[d.ID]
		}
	}
	return best
}

func normName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '('); i > 0 { // CDP "switch(SERIAL)"
		s = s[:i]
	}
	return s
}
