package discovery

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/s835773/OctoLAN/internal/model"
)

// SNMP OIDs (no leading dot; gosnmp returns names with one).
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysContact  = "1.3.6.1.2.1.1.4.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidSysLocation = "1.3.6.1.2.1.1.6.0"
	oidSysServices = "1.3.6.1.2.1.1.7.0"

	oidIfDescr      = "1.3.6.1.2.1.2.2.1.2"
	oidIfType       = "1.3.6.1.2.1.2.2.1.3"
	oidIfSpeed      = "1.3.6.1.2.1.2.2.1.5"
	oidIfPhys       = "1.3.6.1.2.1.2.2.1.6"
	oidIfAdmin      = "1.3.6.1.2.1.2.2.1.7"
	oidIfOper       = "1.3.6.1.2.1.2.2.1.8"
	oidIfInErr      = "1.3.6.1.2.1.2.2.1.14"
	oidIfOutErr     = "1.3.6.1.2.1.2.2.1.20"
	oidIfName       = "1.3.6.1.2.1.31.1.1.1.1"
	oidIfHCIn       = "1.3.6.1.2.1.31.1.1.1.6"
	oidIfHCOut      = "1.3.6.1.2.1.31.1.1.1.10"
	oidIfHighSpeed  = "1.3.6.1.2.1.31.1.1.1.15"
	oidIfAlias      = "1.3.6.1.2.1.31.1.1.1.18"
	oidIPAdEntIf    = "1.3.6.1.2.1.4.20.1.2"
	oidIPNetToMedia = "1.3.6.1.2.1.4.22.1.2"

	oidLldpLocPortID   = "1.0.8802.1.1.2.1.3.7.1.3"
	oidLldpLocPortDesc = "1.0.8802.1.1.2.1.3.7.1.4"
	oidLldpRem         = "1.0.8802.1.1.2.1.4.1.1"
	oidLldpRemManAddr  = "1.0.8802.1.1.2.1.4.2.1.3"

	oidCdpCache = "1.3.6.1.4.1.9.9.23.1.2.1.1"

	oidDot1dBasePortIf = "1.3.6.1.2.1.17.1.4.1.2"
	oidDot1dTpFdbPort  = "1.3.6.1.2.1.17.4.3.1.2"
	oidDot1qTpFdbPort  = "1.3.6.1.2.1.17.7.1.2.2.1.2"
	oidDot1qVlanName   = "1.3.6.1.2.1.17.7.1.4.3.1.1"
	oidDot1qPvid       = "1.3.6.1.2.1.17.7.1.4.5.1.1"
	oidCiscoVtpVlan    = "1.3.6.1.4.1.9.9.46.1.3.1.1.4.1"

	oidEntClass  = "1.3.6.1.2.1.47.1.1.1.1.5"
	oidEntSWRev  = "1.3.6.1.2.1.47.1.1.1.1.10"
	oidEntSerial = "1.3.6.1.2.1.47.1.1.1.1.11"
	oidEntModel  = "1.3.6.1.2.1.47.1.1.1.1.13"

	oidUPSModel = "1.3.6.1.2.1.33.1.1.2.0"
	oidPrtName  = "1.3.6.1.2.1.43.5.1.1.16.1"
)

// SNMPCreds are tried in order: v3 users first, then v2c communities.
type SNMPCreds struct {
	Communities []string
	V3          []model.SNMPv3Cred
}

// DefaultCommunities are what an assessment should check for.
var DefaultCommunities = []string{"public", "private"}

// SNMPResult is everything polled from one agent.
type SNMPResult struct {
	Info       model.SNMPInfo
	Location   string
	Contact    string
	Interfaces []model.Interface
	Neighbors  []model.Neighbor
	FDB        []model.FDBEntry
	VLANs      []model.VLAN
	ARP        []ARPResult // router/L3 switch ARP cache: hosts on other subnets
	OwnIPs     []string
	Model      string
	Serial     string
	Firmware   string
	Extra      string // printer/UPS names
}

func newClient(ip netip.Addr, timeout time.Duration) *gosnmp.GoSNMP {
	return &gosnmp.GoSNMP{
		Target:         ip.String(),
		Port:           161,
		Timeout:        timeout,
		Retries:        1,
		MaxRepetitions: 25,
		MaxOids:        gosnmp.MaxOids,
	}
}

func v3Client(ip netip.Addr, timeout time.Duration, c model.SNMPv3Cred) *gosnmp.GoSNMP {
	g := newClient(ip, timeout)
	g.Version = gosnmp.Version3
	g.SecurityModel = gosnmp.UserSecurityModel
	sp := &gosnmp.UsmSecurityParameters{UserName: c.User}
	g.MsgFlags = gosnmp.NoAuthNoPriv
	if c.AuthPass != "" {
		g.MsgFlags = gosnmp.AuthNoPriv
		sp.AuthenticationPassphrase = c.AuthPass
		switch strings.ToUpper(c.AuthProto) {
		case "MD5":
			sp.AuthenticationProtocol = gosnmp.MD5
		case "SHA256":
			sp.AuthenticationProtocol = gosnmp.SHA256
		case "SHA384":
			sp.AuthenticationProtocol = gosnmp.SHA384
		case "SHA512":
			sp.AuthenticationProtocol = gosnmp.SHA512
		default:
			sp.AuthenticationProtocol = gosnmp.SHA
		}
		if c.PrivPass != "" {
			g.MsgFlags = gosnmp.AuthPriv
			sp.PrivacyPassphrase = c.PrivPass
			switch strings.ToUpper(c.PrivProto) {
			case "DES":
				sp.PrivacyProtocol = gosnmp.DES
			case "AES192":
				sp.PrivacyProtocol = gosnmp.AES192
			case "AES256":
				sp.PrivacyProtocol = gosnmp.AES256
			default:
				sp.PrivacyProtocol = gosnmp.AES
			}
		}
	}
	g.SecurityParameters = sp
	return g
}

// SNMPConnect finds working credentials for ip. It returns a connected
// client (caller must close g.Conn) and the system group.
func SNMPConnect(ctx context.Context, ip netip.Addr, creds SNMPCreds, timeout time.Duration) (*gosnmp.GoSNMP, *model.SNMPInfo) {
	try := func(g *gosnmp.GoSNMP) *model.SNMPInfo {
		if ctx.Err() != nil {
			return nil
		}
		g.Context = ctx
		if err := g.Connect(); err != nil {
			return nil
		}
		pkt, err := g.Get([]string{oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysName, oidSysServices})
		if err != nil || pkt == nil || pkt.Error != gosnmp.NoError || len(pkt.Variables) == 0 {
			g.Conn.Close()
			return nil
		}
		info := &model.SNMPInfo{}
		got := false
		for _, v := range pkt.Variables {
			if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance || v.Type == gosnmp.Null {
				continue
			}
			got = true
			switch strings.TrimPrefix(v.Name, ".") {
			case oidSysDescr:
				info.SysDescr = cleanSNMPString(v.Value)
			case oidSysObjectID:
				info.SysObjectID = strings.TrimPrefix(fmt.Sprint(v.Value), ".")
			case oidSysUpTime:
				info.SysUpTime = gosnmp.ToBigInt(v.Value).Int64() / 100
			case oidSysName:
				info.SysName = cleanSNMPString(v.Value)
			case oidSysServices:
				info.SysServices = int(gosnmp.ToBigInt(v.Value).Int64())
			}
		}
		if !got {
			g.Conn.Close()
			return nil
		}
		return info
	}
	for _, c := range creds.V3 {
		g := v3Client(ip, timeout, c)
		if info := try(g); info != nil {
			info.Version = "v3"
			return g, info
		}
	}
	for _, comm := range creds.Communities {
		for _, ver := range []gosnmp.SnmpVersion{gosnmp.Version2c, gosnmp.Version1} {
			g := newClient(ip, timeout)
			g.Version = ver
			g.Community = comm
			if info := try(g); info != nil {
				info.Version = map[gosnmp.SnmpVersion]string{gosnmp.Version2c: "v2c", gosnmp.Version1: "v1"}[ver]
				info.Community = comm
				info.DefaultComm = comm == "public" || comm == "private"
				return g, info
			}
			if ctx.Err() != nil {
				return nil, nil
			}
		}
	}
	return nil, nil
}

func cleanSNMPString(v any) string {
	var s string
	switch t := v.(type) {
	case []byte:
		s = string(t)
	case string:
		s = t
	default:
		s = fmt.Sprint(v)
	}
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return ' '
		}
		if r < 32 {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(strings.Join(strings.Fields(s), " "))
}

func walk(g *gosnmp.GoSNMP, oid string, limit int) []gosnmp.SnmpPDU {
	var out []gosnmp.SnmpPDU
	fn := func(p gosnmp.SnmpPDU) error {
		out = append(out, p)
		if len(out) >= limit {
			return errWalkLimit
		}
		return nil
	}
	if g.Version == gosnmp.Version1 {
		_ = g.Walk(oid, fn)
	} else {
		_ = g.BulkWalk(oid, fn)
	}
	return out
}

const errWalkLimit = errString("walk limit")

// suffix returns the OID index after base.
func suffix(name, base string) string {
	return strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(name, "."), base), ".")
}

func idxInt(name, base string) int {
	n, _ := strconv.Atoi(suffix(name, base))
	return n
}

func macFromIndex(parts []string) string {
	if len(parts) < 6 {
		return ""
	}
	b := make(net.HardwareAddr, 6)
	for i := 0; i < 6; i++ {
		v, err := strconv.Atoi(parts[len(parts)-6+i])
		if err != nil || v > 255 {
			return ""
		}
		b[i] = byte(v)
	}
	return b.String()
}

func bytesOf(v any) []byte {
	switch t := v.(type) {
	case []byte:
		return t
	case string:
		return []byte(t)
	}
	return nil
}

func toInt(v any) int64 { return gosnmp.ToBigInt(v).Int64() }

// SNMPPoll gathers interfaces, neighbors, forwarding tables, VLANs and
// ARP caches from a connected agent. Each table is bounded so a huge
// core switch can't stall the assessment.
func SNMPPoll(ctx context.Context, g *gosnmp.GoSNMP, info *model.SNMPInfo) *SNMPResult {
	res := &SNMPResult{Info: *info}

	if pkt, err := g.Get([]string{oidSysLocation, oidSysContact}); err == nil {
		for _, v := range pkt.Variables {
			s := cleanSNMPString(v.Value)
			if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance {
				continue
			}
			switch strings.TrimPrefix(v.Name, ".") {
			case oidSysLocation:
				res.Location = s
			case oidSysContact:
				res.Contact = s
			}
		}
	}

	// Interfaces
	ifs := map[int]*model.Interface{}
	get := func(idx int) *model.Interface {
		if ifs[idx] == nil {
			ifs[idx] = &model.Interface{Index: idx}
		}
		return ifs[idx]
	}
	const ifLimit = 2048
	for _, p := range walk(g, oidIfDescr, ifLimit) {
		get(idxInt(p.Name, oidIfDescr)).Name = cleanSNMPString(p.Value)
	}
	for _, p := range walk(g, oidIfName, ifLimit) {
		if s := cleanSNMPString(p.Value); s != "" {
			get(idxInt(p.Name, oidIfName)).Name = s
		}
	}
	for _, p := range walk(g, oidIfAlias, ifLimit) {
		get(idxInt(p.Name, oidIfAlias)).Alias = cleanSNMPString(p.Value)
	}
	for _, p := range walk(g, oidIfType, ifLimit) {
		get(idxInt(p.Name, oidIfType)).Type = int(toInt(p.Value))
	}
	for _, p := range walk(g, oidIfSpeed, ifLimit) {
		get(idxInt(p.Name, oidIfSpeed)).SpeedMbps = toInt(p.Value) / 1_000_000
	}
	for _, p := range walk(g, oidIfHighSpeed, ifLimit) {
		if v := toInt(p.Value); v > 0 {
			get(idxInt(p.Name, oidIfHighSpeed)).SpeedMbps = v
		}
	}
	for _, p := range walk(g, oidIfPhys, ifLimit) {
		if b := bytesOf(p.Value); len(b) == 6 {
			get(idxInt(p.Name, oidIfPhys)).MAC = net.HardwareAddr(b).String()
		}
	}
	for _, p := range walk(g, oidIfAdmin, ifLimit) {
		get(idxInt(p.Name, oidIfAdmin)).AdminUp = toInt(p.Value) == 1
	}
	for _, p := range walk(g, oidIfOper, ifLimit) {
		get(idxInt(p.Name, oidIfOper)).OperUp = toInt(p.Value) == 1
	}
	for _, p := range walk(g, oidIfHCIn, ifLimit) {
		get(idxInt(p.Name, oidIfHCIn)).InOctets = gosnmp.ToBigInt(p.Value).Uint64()
	}
	for _, p := range walk(g, oidIfHCOut, ifLimit) {
		get(idxInt(p.Name, oidIfHCOut)).OutOctets = gosnmp.ToBigInt(p.Value).Uint64()
	}
	for _, p := range walk(g, oidIfInErr, ifLimit) {
		get(idxInt(p.Name, oidIfInErr)).InErrors = gosnmp.ToBigInt(p.Value).Uint64()
	}
	for _, p := range walk(g, oidIfOutErr, ifLimit) {
		get(idxInt(p.Name, oidIfOutErr)).OutErrors = gosnmp.ToBigInt(p.Value).Uint64()
	}
	ifName := func(idx int) string {
		if i := ifs[idx]; i != nil && i.Name != "" {
			return i.Name
		}
		if idx == 0 {
			return ""
		}
		return fmt.Sprintf("if%d", idx)
	}

	// Own IP addresses (lets topology match LLDP management addresses).
	for _, p := range walk(g, oidIPAdEntIf, 512) {
		ip := suffix(p.Name, oidIPAdEntIf)
		if a, err := netip.ParseAddr(ip); err == nil && !a.IsLoopback() {
			res.OwnIPs = append(res.OwnIPs, a.String())
		}
	}

	// Bridge port -> ifIndex
	bp2if := map[int]int{}
	for _, p := range walk(g, oidDot1dBasePortIf, 4096) {
		bp2if[idxInt(p.Name, oidDot1dBasePortIf)] = int(toInt(p.Value))
	}
	portName := func(bp int) string {
		if ifi, ok := bp2if[bp]; ok {
			return ifName(ifi)
		}
		return fmt.Sprintf("port%d", bp)
	}

	// PVIDs
	for _, p := range walk(g, oidDot1qPvid, 4096) {
		bp := idxInt(p.Name, oidDot1qPvid)
		if ifi, ok := bp2if[bp]; ok {
			get(ifi).PVID = int(toInt(p.Value))
		}
	}

	// LLDP local port numbers -> names
	lldpLocal := map[string]string{}
	for _, p := range walk(g, oidLldpLocPortDesc, 1024) {
		lldpLocal[suffix(p.Name, oidLldpLocPortDesc)] = cleanSNMPString(p.Value)
	}
	for _, p := range walk(g, oidLldpLocPortID, 1024) {
		k := suffix(p.Name, oidLldpLocPortID)
		if lldpLocal[k] == "" {
			lldpLocal[k] = printableID(bytesOf(p.Value))
		}
	}

	// LLDP remote table: index = timeMark.localPort.remIndex
	type remKey struct{ local, idx string }
	rem := map[remKey]*model.Neighbor{}
	for _, p := range walk(g, oidLldpRem, 4096) {
		s := suffix(p.Name, oidLldpRem)
		parts := strings.Split(s, ".")
		if len(parts) < 4 {
			continue
		}
		col, local, idx := parts[0], parts[2], parts[3]
		k := remKey{local, idx}
		n := rem[k]
		if n == nil {
			n = &model.Neighbor{Protocol: "lldp", LocalPort: lldpLocal[local]}
			if n.LocalPort == "" {
				if li, err := strconv.Atoi(local); err == nil {
					n.LocalPort = ifName(li)
				}
			}
			rem[k] = n
		}
		switch col {
		case "5":
			n.RemoteChassis = chassisString(bytesOf(p.Value))
		case "7":
			n.RemotePort = printableID(bytesOf(p.Value))
		case "8":
			if d := cleanSNMPString(p.Value); d != "" && (n.RemotePort == "" || isHexish(n.RemotePort)) {
				n.RemotePort = d
			}
		case "9":
			n.RemoteName = cleanSNMPString(p.Value)
		case "10":
			n.RemoteDescr = cleanSNMPString(p.Value)
		case "12":
			n.RemoteCaps = lldpCaps(bytesOf(p.Value))
		}
	}
	// Management addresses: index ...timeMark.localPort.remIndex.subtype.len.a.b.c.d
	for _, p := range walk(g, oidLldpRemManAddr, 4096) {
		parts := strings.Split(suffix(p.Name, oidLldpRemManAddr), ".")
		if len(parts) >= 9 && parts[3] == "1" && parts[4] == "4" {
			k := remKey{parts[1], parts[2]}
			if n := rem[k]; n != nil && n.RemoteIP == "" {
				n.RemoteIP = strings.Join(parts[5:9], ".")
			}
		}
	}
	for _, n := range rem {
		res.Neighbors = append(res.Neighbors, *n)
	}

	// CDP cache: index = ifIndex.deviceIndex
	cdp := map[string]*model.Neighbor{}
	for _, p := range walk(g, oidCdpCache, 4096) {
		parts := strings.Split(suffix(p.Name, oidCdpCache), ".")
		if len(parts) < 3 {
			continue
		}
		col, key := parts[0], parts[1]+"."+parts[2]
		n := cdp[key]
		if n == nil {
			li, _ := strconv.Atoi(parts[1])
			n = &model.Neighbor{Protocol: "cdp", LocalPort: ifName(li)}
			cdp[key] = n
		}
		switch col {
		case "4":
			if b := bytesOf(p.Value); len(b) == 4 {
				n.RemoteIP = net.IP(b).String()
			}
		case "5":
			n.RemoteDescr = cleanSNMPString(p.Value)
		case "6":
			n.RemoteName = cleanSNMPString(p.Value)
		case "7":
			n.RemotePort = cleanSNMPString(p.Value)
		case "8":
			if n.RemoteDescr == "" {
				n.RemoteDescr = cleanSNMPString(p.Value)
			}
			n.RemoteCaps = cleanSNMPString(p.Value)
		}
	}
	for _, n := range cdp {
		res.Neighbors = append(res.Neighbors, *n)
	}

	// Forwarding database (Q-BRIDGE first, then classic BRIDGE-MIB).
	const fdbLimit = 16384
	for _, p := range walk(g, oidDot1qTpFdbPort, fdbLimit) {
		parts := strings.Split(suffix(p.Name, oidDot1qTpFdbPort), ".")
		mac := macFromIndex(parts)
		bp := int(toInt(p.Value))
		if mac == "" || bp == 0 {
			continue
		}
		vlan, _ := strconv.Atoi(parts[0])
		res.FDB = append(res.FDB, model.FDBEntry{MAC: mac, Port: portName(bp), VLAN: vlan})
	}
	if len(res.FDB) == 0 {
		for _, p := range walk(g, oidDot1dTpFdbPort, fdbLimit) {
			mac := macFromIndex(strings.Split(suffix(p.Name, oidDot1dTpFdbPort), "."))
			bp := int(toInt(p.Value))
			if mac == "" || bp == 0 {
				continue
			}
			res.FDB = append(res.FDB, model.FDBEntry{MAC: mac, Port: portName(bp)})
		}
	}

	// VLAN names
	for _, p := range walk(g, oidDot1qVlanName, 4096) {
		id := idxInt(p.Name, oidDot1qVlanName)
		res.VLANs = append(res.VLANs, model.VLAN{ID: id, Name: cleanSNMPString(p.Value), Source: "snmp"})
	}
	if len(res.VLANs) == 0 {
		for _, p := range walk(g, oidCiscoVtpVlan, 4096) {
			id := idxInt(p.Name, oidCiscoVtpVlan)
			res.VLANs = append(res.VLANs, model.VLAN{ID: id, Name: cleanSNMPString(p.Value), Source: "snmp"})
		}
	}

	// ARP cache of routers / L3 switches: index = ifIndex.a.b.c.d
	for _, p := range walk(g, oidIPNetToMedia, 16384) {
		parts := strings.Split(suffix(p.Name, oidIPNetToMedia), ".")
		if len(parts) < 5 {
			continue
		}
		ip, err := netip.ParseAddr(strings.Join(parts[len(parts)-4:], "."))
		b := bytesOf(p.Value)
		if err != nil || len(b) != 6 {
			continue
		}
		res.ARP = append(res.ARP, ARPResult{IP: ip, MAC: net.HardwareAddr(b)})
	}

	// Physical entity: model, serial, firmware of the first chassis.
	chassis := ""
	for _, p := range walk(g, oidEntClass, 512) {
		if toInt(p.Value) == 3 {
			chassis = suffix(p.Name, oidEntClass)
			break
		}
	}
	if chassis != "" {
		if pkt, err := g.Get([]string{oidEntModel + "." + chassis, oidEntSerial + "." + chassis, oidEntSWRev + "." + chassis}); err == nil {
			for _, v := range pkt.Variables {
				s := cleanSNMPString(v.Value)
				if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance || s == "" {
					continue
				}
				switch {
				case strings.HasPrefix(strings.TrimPrefix(v.Name, "."), oidEntModel):
					res.Model = s
				case strings.HasPrefix(strings.TrimPrefix(v.Name, "."), oidEntSerial):
					res.Serial = s
				case strings.HasPrefix(strings.TrimPrefix(v.Name, "."), oidEntSWRev):
					res.Firmware = s
				}
			}
		}
	}
	if pkt, err := g.Get([]string{oidUPSModel, oidPrtName}); err == nil {
		for _, v := range pkt.Variables {
			if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance || v.Type == gosnmp.Null {
				continue
			}
			if s := cleanSNMPString(v.Value); s != "" {
				if strings.TrimPrefix(v.Name, ".") == oidUPSModel {
					res.Extra = "UPS " + s
				} else {
					res.Extra = "Printer " + s
				}
			}
		}
	}

	keys := make([]int, 0, len(ifs))
	for k := range ifs {
		if k > 0 {
			keys = append(keys, k)
		}
	}
	sort.Ints(keys)
	for _, k := range keys {
		res.Interfaces = append(res.Interfaces, *ifs[k])
	}
	return res
}

func printableID(b []byte) string {
	if len(b) == 6 {
		nonPrint := false
		for _, c := range b {
			if c < 32 || c > 126 {
				nonPrint = true
			}
		}
		if nonPrint {
			return net.HardwareAddr(b).String()
		}
	}
	return cleanSNMPString(b)
}

func chassisString(b []byte) string {
	if len(b) == 6 {
		return net.HardwareAddr(b).String()
	}
	return printableID(b)
}

func isHexish(s string) bool {
	_, err := net.ParseMAC(s)
	return err == nil
}

func lldpCaps(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	names := []string{"other", "repeater", "bridge", "wlan-ap", "router", "telephone", "docsis", "station"}
	var out []string
	for i, n := range names {
		if b[0]&(0x80>>i) != 0 {
			out = append(out, n)
		}
	}
	return strings.Join(out, ",")
}
