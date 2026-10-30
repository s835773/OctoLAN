// Command docsdemo builds a fictional sample site ("Riverside Dental
// Group") for the README screenshots and example report. The devices are
// invented, but they run through OctoLAN's real classifier, topology
// builder and posture checks, so the output looks exactly like a real
// assessment.
//
//	go run ./tools/docsdemo docs/sample/session.json
//	go run ./tools/docsdemo -vault /tmp/demo-data docs/sample/session.json
//
// -vault also writes a matching fictional credential vault (passphrase
// "sample passphrase") under DIR/<site>/ for screenshots of the
// Credentials page.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/s835773/OctoLAN/internal/collect"
	"github.com/s835773/OctoLAN/internal/engine"
	"github.com/s835773/OctoLAN/internal/model"
	"github.com/s835773/OctoLAN/internal/store"
	"github.com/s835773/OctoLAN/internal/vault"
)

type dev struct {
	ip, mac, name string
	ports         []int
	banners       map[int]string
	set           func(d *model.Device)
}

var svc = map[int]string{21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 135: "msrpc", 139: "netbios-ssn",
	443: "https", 445: "smb", 554: "rtsp", 631: "ipp", 3389: "rdp", 5000: "upnp/synology", 5001: "synology-https",
	5060: "sip", 8000: "http-alt", 9100: "jetdirect", 88: "kerberos", 389: "ldap", 53: "dns", 8443: "https-alt"}

// ttlFor gives each sample device a realistic observed TTL: 128 for
// Windows, 255 for network gear, 64 for Linux/embedded/Apple.
func ttlFor(name string, ports []int) int {
	for _, p := range ports {
		if p == 3389 || p == 135 {
			return 128
		}
	}
	switch {
	case strings.HasPrefix(name, "rdg-") && strings.Contains(name, "sw"), strings.HasPrefix(name, "rdg-fw"):
		return 255
	}
	return 64
}

func main() {
	vaultDir := flag.String("vault", "", "also write a fictional sample vault under this data directory")
	flag.Parse()
	out := "docs/sample/session.json"
	if flag.NArg() > 0 {
		out = flag.Arg(0)
	}
	st := store.New()
	st.SetSite("Riverside Dental Group (sample data)")
	e := engine.New(st, "v2.0.0", os.TempDir())
	now := time.Now()
	day := 24 * time.Hour

	st.SetCaps(model.Capabilities{OS: "windows", Arch: "amd64", Hostname: "TECH-LAPTOP-07", RawCapture: true, ICMPMode: "windows-api",
		DefaultIface: "Ethernet", Interfaces: []model.IfInfo{{Name: "Ethernet", Addrs: []string{"10.20.0.57/24"}, Gateway: "10.20.0.1", Up: true}}})
	st.AddSubnet(model.Subnet{CIDR: "10.20.0.0/24", Gateway: "10.20.0.1", Interface: "Ethernet", Local: true, Hosts: 254})
	st.AddSubnet(model.Subnet{CIDR: "10.20.10.0/24", Gateway: "10.20.10.1", Hosts: 254})

	win := func(mm, build string) func(d *model.Device) {
		return func(d *model.Device) { d.SMB = &model.SMBInfo{Dialect: "SMB 3.0.2", OSMajorMinor: mm, OSBuild: build} }
	}
	cert := func(port int, subj string, notAfter time.Time, self bool) model.TLSInfo {
		return model.TLSInfo{Port: port, Subject: subj, Issuer: subj, NotAfter: notAfter, SelfSigned: self, Version: "TLS 1.2"}
	}
	core := "00:00:0c:4a:21:10"
	devs := []dev{
		{"10.20.0.1", "00:09:0f:aa:10:01", "rdg-fw01", []int{443, 8443, 22}, map[int]string{443: "HTTP/1.1 200 OK | Title: FortiGate"}, func(d *model.Device) {
			d.IsGateway = true
			d.SNMP = &model.SNMPInfo{Version: "v2c", SysDescr: "FortiGate-60F v7.2.8,build1639", SysObjectID: "1.3.6.1.4.1.12356.101.1.1", SysName: "rdg-fw01", SysUpTime: 41 * 86400, SysServices: 78}
			d.Model, d.Serial, d.Firmware = "FortiGate-60F", "FGT60FTK2209XXXX", "v7.2.8"
			d.TLS = []model.TLSInfo{cert(443, "rdg-fw01", now.Add(-12*day), true)}
			d.Services = []model.Service{{Type: "ssdp", Name: "device:InternetGatewayDevice:1", Detail: "FortiOS UPnP/1.0"}}
		}},
		{"10.20.0.2", core, "rdg-core-sw01", []int{22, 23, 80, 443}, nil, func(d *model.Device) {
			d.SNMP = &model.SNMPInfo{Version: "v2c", DefaultComm: true, SysDescr: "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E4", SysObjectID: "1.3.6.1.4.1.9.1.1208", SysName: "rdg-core-sw01", SysUpTime: 512 * 86400, SysServices: 2}
			d.Model, d.Serial, d.Firmware = "WS-C2960X-48FPD-L", "FOC2138XXXX", "15.2(7)E4"
			d.Location = "Server closet, rack 1"
			d.Neighbors = []model.Neighbor{
				{Protocol: "cdp", LocalPort: "Gi1/0/48", RemoteName: "rdg-fw01", RemoteChassis: "00:09:0f:aa:10:01", RemotePort: "port1", RemoteIP: "10.20.0.1"},
				{Protocol: "lldp", LocalPort: "Gi1/0/47", RemoteName: "rdg-sw02", RemoteChassis: "00:00:0c:4a:21:20", RemotePort: "Gi0/10", RemoteIP: "10.20.0.3"},
				{Protocol: "lldp", LocalPort: "Gi1/0/40", RemoteName: "AP-Front-Desk", RemoteChassis: "00:15:6d:31:00:01", RemotePort: "eth0", RemoteIP: "10.20.0.11", RemoteCaps: "wlan-ap"},
			}
			for i := 1; i <= 20; i++ {
				d.Interfaces = append(d.Interfaces, model.Interface{Index: 10100 + i, Name: fmt.Sprintf("Gi1/0/%d", i), AdminUp: true, OperUp: i%4 != 0, SpeedMbps: 1000, PVID: 1, InOctets: uint64(i) * 9e9, OutOctets: uint64(i) * 4e9})
			}
			d.Interfaces[6].InErrors = 48211
			d.VLANs = []model.VLAN{{ID: 1, Name: "default"}, {ID: 10, Name: "VOICE"}, {ID: 20, Name: "CAMERAS"}}
		}},
		{"10.20.0.3", "00:00:0c:4a:21:20", "rdg-sw02", []int{22}, nil, func(d *model.Device) {
			d.SNMP = &model.SNMPInfo{Version: "v2c", SysDescr: "Cisco IOS Software, C1000 Software (C1000-UNIVERSALK9-M), Version 15.2(7)E8", SysName: "rdg-sw02", SysUpTime: 88 * 86400, SysServices: 2}
			d.Model = "C1000-24P-4G-L"
		}},
		{"10.20.0.11", "00:15:6d:31:00:01", "AP-Front-Desk", []int{22}, nil, nil},
		{"10.20.0.12", "00:15:6d:31:00:02", "AP-Operatory", []int{22}, nil, func(d *model.Device) { d.Type = model.TypeAccessPoint }},
		{"10.20.0.10", "00:06:5b:10:00:10", "RDG-DC01", []int{53, 88, 135, 139, 389, 445, 3389}, nil, win("10.0", "20348")},
		{"10.20.0.15", "00:06:5b:10:00:15", "RDG-FS01", []int{135, 139, 445, 3389, 21}, map[int]string{21: "220 Microsoft FTP Service"}, func(d *model.Device) {
			d.SMB = &model.SMBInfo{SMB1: true, Dialect: "SMB 3.0.2", OSMajorMinor: "6.3", OSBuild: "9600", NetBIOSDom: "RIVERSIDE"}
			d.Type = model.TypeServer
			d.Notes = "Dentrix database server"
		}},
		{"10.20.0.20", "00:11:32:aa:bb:20", "rdg-nas01", []int{22, 80, 139, 445, 5000, 5001}, map[int]string{5000: "HTTP/1.1 200 OK | Server: nginx | Title: Synology DiskStation"}, func(d *model.Device) {
			d.TLS = []model.TLSInfo{cert(5001, "synology", now.Add(19*day), true)}
		}},
		{"10.20.0.25", "00:c0:b7:55:00:25", "ups-closet", []int{80}, nil, func(d *model.Device) {
			d.SNMP = &model.SNMPInfo{Version: "v1", DefaultComm: true, SysDescr: "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.4.6 PN:apc_hw05_aos_646.bin)", SysName: "ups-closet"}
		}},
		{"10.20.0.30", "00:01:e6:30:00:30", "HP-Front-Office", []int{80, 443, 631, 9100}, map[int]string{80: "HTTP/1.1 200 OK | Title: HP LaserJet Pro M404dn"}, func(d *model.Device) { d.Model = "HP LaserJet Pro M404dn" }},
		{"10.20.0.31", "00:01:e6:30:00:31", "HP-Xray-Room", []int{80, 9100, 23}, nil, nil},
		{"10.20.0.40", "00:bc:99:40:00:40", "NVR-01", []int{80, 554, 8000}, map[int]string{80: "HTTP/1.1 200 OK | Server: webserver | Title: NVR"}, nil},
		{"10.20.0.41", "00:bc:99:40:00:41", "cam-lobby", []int{80, 554}, nil, nil},
		{"10.20.0.42", "00:bc:99:40:00:42", "cam-parking", []int{80, 554}, nil, nil},
		{"10.20.0.43", "00:bc:99:40:00:43", "cam-rear-door", []int{80, 554}, nil, nil},
	}
	for i := 0; i < 4; i++ {
		devs = append(devs, dev{fmt.Sprintf("10.20.0.%d", 60+i), fmt.Sprintf("24:9a:d8:00:00:%02x", 0x60+i), fmt.Sprintf("SIP-T54W-%d", i+1), []int{80, 443, 5060}, nil, nil})
	}
	builds := []string{"26100", "26100", "22631", "26100", "19045", "26100", "22631", "26100", "19045"}
	for i, b := range builds {
		devs = append(devs, dev{fmt.Sprintf("10.20.0.%d", 100+i), fmt.Sprintf("00:12:fe:00:01:%02x", i), fmt.Sprintf("RDG-WS%02d", i+1), []int{135, 139, 445, 3389}, nil, win("10.0", b)})
	}
	devs = append(devs,
		dev{"10.20.0.120", "00:03:93:00:01:20", "Dr-Patel-MacBook", nil, nil, func(d *model.Device) { d.Model = "Mac15,6" }},
		dev{"10.20.0.130", "00:0e:58:00:01:30", "Sonos-Waiting-Room", nil, nil, func(d *model.Device) {
			d.Services = []model.Service{{Type: "_sonos._tcp", Name: "Waiting Room"}}
		}},
		dev{"10.20.0.140", "00:4b:12:00:01:40", "", []int{80}, nil, nil},
		dev{"10.20.0.150", "da:a1:19:00:01:50", "iPhone", []int{62078}, nil, nil},
		dev{"10.20.0.199", "", "", nil, nil, nil},
		dev{"10.20.10.21", "", "RDG-XRAY-ACQ", []int{135, 139, 445, 3389}, nil, win("6.1", "7601")},
		dev{"10.20.10.22", "", "", []int{104, 80}, map[int]string{80: "HTTP/1.1 200 OK | Title: Imaging Device"}, nil},
	)

	rtt := []int64{410, 380, 520, 1200, 1350, 290, 330, 610, 900, 1800, 2100, 740, 820, 790, 860}
	for i, d := range devs {
		d := d
		src := model.SrcARP
		if d.mac == "" {
			src = model.SrcSNMP + "-arp"
		}
		st.Observe(d.ip, d.mac, src, func(x *model.Device) {
			if d.name != "" {
				store.AddName(x, d.name)
			}
			x.RTTMicro = rtt[i%len(rtt)] + int64(i*37)
			x.TTL = ttlFor(d.name, d.ports)
			for _, p := range d.ports {
				x.Ports = append(x.Ports, model.Port{Port: p, Proto: "tcp", Service: svc[p], Banner: d.banners[p]})
			}
			store.AddSource(x, model.SrcICMP)
			if len(d.ports) > 0 {
				store.AddSource(x, model.SrcTCP)
			}
			if d.set != nil {
				d.set(x)
			}
			if x.SNMP != nil {
				store.AddSource(x, model.SrcSNMP)
			}
		})
	}
	// Switch MAC table: endpoints on their edge ports.
	coreID := st.FindByMAC(core)
	st.Update(coreID, func(d *model.Device) {
		port := 1
		for _, x := range devs {
			if x.mac == "" || x.mac == core || x.ip == "10.20.0.1" || x.ip == "10.20.0.3" || x.ip == "10.20.0.11" {
				continue
			}
			p := fmt.Sprintf("Gi1/0/%d", port)
			if port > 20 {
				// Phones and workstations behind sw02 appear on the uplink.
				p = "Gi1/0/47"
			}
			d.FDB = append(d.FDB, model.FDBEntry{MAC: x.mac, Port: p, VLAN: 1})
			port++
		}
		for i := 0; i < 8; i++ { // uplink carries more MACs than any edge port
			d.FDB = append(d.FDB, model.FDBEntry{MAC: fmt.Sprintf("02:00:00:00:47:%02x", i), Port: "Gi1/0/47", VLAN: 1})
		}
	})
	self := st.Observe("10.20.0.57", "00:12:fe:99:00:57", model.SrcLocalHost, func(d *model.Device) {
		d.IsSelf = true
		store.AddName(d, "TECH-LAPTOP-07")
		d.Type = model.TypeWorkstation
		d.OS = model.OSGuess{Family: "Windows", Name: "Windows 11 24H2", Confidence: 100}
		d.Neighbors = []model.Neighbor{{Protocol: "cdp", LocalPort: "Ethernet", RemoteName: "rdg-core-sw01", RemoteChassis: core, RemotePort: "GigabitEthernet1/0/24", NativeVLAN: 1}}
	})
	_ = self

	st.ObserveDHCPServer(model.DHCPServer{IP: "10.20.0.10", Router: "10.20.0.1", DNS: []string{"10.20.0.10"}, Domain: "riverside.local"})
	st.ObserveDHCPServer(model.DHCPServer{IP: "192.168.0.1", MAC: "00:15:6d:ff:00:01", Router: "192.168.0.1", DNS: []string{"192.168.0.1"}})
	for _, v := range []model.VLAN{{ID: 1, Name: "default", Source: "snmp"}, {ID: 10, Name: "VOICE", Source: "snmp"}, {ID: 20, Name: "CAMERAS", Source: "snmp"}} {
		st.ObserveVLAN(v)
	}

	// Storm Guard and NetFlow summaries as they'd look after ~25 minutes.
	var series []model.PPSSample
	for i := 0; i < 300; i++ {
		b := 140 + (i*37)%60
		if i > 180 && i < 196 {
			b = 1400 + (i-180)*90
		}
		series = append(series, model.PPSSample{T: now.Add(time.Duration(i-300) * time.Second).UnixMilli(), Total: 2600 + b, Broadcast: b, Multicast: 310 + (i*11)%40, Unicast: 2200, ARP: 30, Bytes: 1_900_000 + b*90})
	}
	storm := model.StormStatus{Running: true, Interface: "Ethernet", State: "ok", Series: series, Current: series[len(series)-1],
		Peak: model.PPSSample{Broadcast: 2750, Multicast: 340, Dups: 31}, WarnPPS: 1000, CritPPS: 5000,
		STP:            model.STPInfo{Seen: true, Protocol: "RSTP (802.1w)", RootBridge: "32769.00:00:0c:4a:21:20", RootPriority: 32768, RootCost: 4, TopologyChanges: 4, BPDUs: 1310},
		TopBroadcaster: []model.Talker{{Key: "00:bc:99:40:00:40", Label: "Hangzhou Hikvision", Packets: 18211}, {Key: "00:06:5b:10:00:10", Label: "Dell Inc.", Packets: 6033}}}
	flows := model.FlowSummary{Listening: true, ListenAddr: ":2055", Exporters: map[string]uint64{"10.20.0.1": 4120}, TotalFlows: 182340,
		TotalBytes: 61_200_000_000, TotalPackets: 58_000_000, Protocols: map[string]uint64{"TCP": 52e9, "UDP": 9e9},
		TopTalkers: []model.Talker{{Key: "10.20.0.15", Bytes: 18e9}, {Key: "10.20.0.40", Bytes: 14e9}, {Key: "10.20.0.20", Bytes: 9.1e9}, {Key: "10.20.0.105", Bytes: 3.2e9}, {Key: "52.96.164.18", Bytes: 2.9e9}},
		TopApps:    []model.Talker{{Key: "SMB", Bytes: 21e9}, {Key: "HTTPS", Bytes: 17e9}, {Key: "RTSP", Bytes: 12e9}, {Key: "RDP", Bytes: 2.1e9}, {Key: "DNS", Bytes: 0.4e9}}}
	for i := 0; i < 300; i++ {
		v := 38e6 + 22e6*float64((i*7)%13)/13
		if i > 200 && i < 230 {
			v += 160e6 // nightly NAS backup
		}
		flows.Series = append(flows.Series, model.RatePoint{T: now.Add(time.Duration(i-300) * 5 * time.Second).UnixMilli(), Value: v})
	}
	flows.Conversations = []model.Flow{
		{Src: "10.20.0.15", Dst: "10.20.0.20", SrcPort: 49822, DstPort: 445, Proto: 6, Bytes: 9.4e9, Packets: 7.1e6, Exporter: "10.20.0.1", LastSeen: now},
		{Src: "10.20.0.41", Dst: "10.20.0.40", SrcPort: 554, DstPort: 51200, Proto: 6, Bytes: 4.2e9, Packets: 3.3e6, Exporter: "10.20.0.1", LastSeen: now},
		{Src: "10.20.0.105", Dst: "52.96.164.18", SrcPort: 52011, DstPort: 443, Proto: 6, Bytes: 2.9e9, Packets: 2.2e6, Exporter: "10.20.0.1", LastSeen: now},
		{Src: "10.20.0.101", Dst: "10.20.0.15", SrcPort: 50133, DstPort: 3389, Proto: 6, Bytes: 1.1e9, Packets: 1.4e6, Exporter: "10.20.0.1", LastSeen: now},
	}
	flows.Versions = map[string]uint64{"IPFIX": 4120}
	st.StormProvider = func() model.StormStatus { return storm }
	st.FlowProvider = func() model.FlowSummary { return flows }

	// Credentialed results, as if the customer had shared a domain admin
	// and the switch login (secrets live only in the vault).
	b := func(v bool) *bool { return &v }
	winInfo := func(osName, build string, ubr int, lastPatch time.Duration, rtp bool, bitlocker bool, admins int) *model.WindowsInfo {
		w := &model.WindowsInfo{OS: osName, Build: build, UBR: ubr, Manufacturer: "Dell Inc.", Domain: "riverside.local", DomainJoined: true,
			HotfixCount: 38, LastHotfix: now.Add(-lastPatch), LastHotfixID: "KB5044284", DefenderRTP: b(rtp), DefenderOn: b(true), SigAgeDays: 1,
			Firewall: map[string]bool{"Domain": true, "Private": true, "Public": true}, RDPNLA: b(true), RAMGB: 16, CPU: "Intel Core i5-12500",
			BitLocker: []model.DriveCrypt{{Drive: "C:", Protected: bitlocker}}, Disks: []model.Disk{{Drive: "C:", SizeGB: 476, FreeGB: 211}},
			SoftwareCount: 64, Collected: now, InstallDate: now.Add(-700 * day), LastBoot: now.Add(-6 * day), Software: []model.Software{{Name: "Dentrix G7", Version: "7.3", Publisher: "Henry Schein One"},
				{Name: "Google Chrome", Version: "130.0.6723.70", Publisher: "Google LLC"}, {Name: "Microsoft 365 Apps for business", Version: "16.0.18129", Publisher: "Microsoft Corporation"},
				{Name: "Adobe Acrobat Reader", Version: "24.004.20219", Publisher: "Adobe"}, {Name: "ScreenConnect Client", Version: "24.3.7", Publisher: "ConnectWise"}}}
		for i := 0; i < admins; i++ {
			w.Admins = append(w.Admins, []string{`RIVERSIDE\Domain Admins`, `Administrator`, `RIVERSIDE\frontdesk`, `RIVERSIDE\drpatel`, `RIVERSIDE\hygiene1`, `RIVERSIDE\oldvendor`}[i])
		}
		return w
	}
	creds := func(id string, ok bool, method, name string) {
		st.Update(id, func(d *model.Device) {
			cr := model.CredResult{Method: method, CredID: "demo", CredName: name, OK: ok, At: now}
			if !ok {
				cr.Error = "credentials rejected"
			}
			d.CredTries = append(d.CredTries, cr)
		})
	}
	setWin := func(ip string, w *model.WindowsInfo) {
		id := st.FindByIP(ip)
		st.Update(id, func(d *model.Device) { d.Windows = w })
		creds(id, true, "winrm", "Domain admin (RIVERSIDE)")
	}
	setWin("10.20.0.10", winInfo("Microsoft Windows Server 2022 Standard", "20348", 2762, 9*day, true, true, 2))
	fs := winInfo("Microsoft Windows Server 2012 R2 Standard", "9600", 21620, 410*day, true, false, 3)
	fs.PendingReboot = true
	setWin("10.20.0.15", fs)
	for i, ip := range []string{"10.20.0.100", "10.20.0.101", "10.20.0.102", "10.20.0.103", "10.20.0.105", "10.20.0.106", "10.20.0.107"} {
		setWin(ip, winInfo("Microsoft Windows 11 Pro", "26100", 2161, time.Duration(12+i)*day, true, i != 3, 3+i%2))
	}
	ws05 := winInfo("Microsoft Windows 10 Pro", "19045", 5011, 97*day, false, false, 6)
	ws05.AutoLogon = true
	setWin("10.20.0.104", ws05)
	creds(st.FindByIP("10.20.0.108"), false, "winrm", "Domain admin (RIVERSIDE)")

	coreCfg := "hostname rdg-core-sw01\nservice password-encryption\nenable password 7 0822455D0A16\nusername admin privilege 15 password 7 045802150C2E\nsnmp-server community public RO\nip http server\nline vty 0 4\n transport input telnet ssh\nend\n"
	st.Update(coreID, func(d *model.Device) {
		d.NetOS = &model.NetOSInfo{Platform: "cisco-ios", Version: "15.2(7)E4", Model: "WS-C2960X-48FPD-L", Serial: "FOC2138X0AB", Uptime: "1 year, 17 weeks, 3 days", Collected: now}
		d.Config = &model.ConfigInfo{Platform: "cisco-ios", Lines: strings.Count(coreCfg, "\n") + 1, SHA256: collect.ConfigHash(coreCfg), Captured: now, Changed: true,
			Issues: collect.AuditConfig(collect.PlatCiscoIOS, coreCfg)}
	})
	creds(coreID, true, "ssh", "Core switches (netadmin)")

	// Analysis runs the real classifier, topology builder and posture checks.
	e.Analyze()

	start := now.Add(-26 * time.Minute)
	phases := []model.PhaseStatus{
		{Name: "Prepare", State: "done", Detail: "Ethernet (10.20.0.57) · 508 targets (254 local, 254 routed)", Duration: 40},
		{Name: "ARP sweep", State: "done", Detail: "38 hosts via raw ARP frames", Duration: 3900},
		{Name: "Ping sweep", State: "done", Detail: "31 replies (windows-api ICMP)", Duration: 4100},
		{Name: "TCP discovery", State: "done", Detail: "4 additional hosts found", Duration: 21000},
		{Name: "Service scan", State: "done", Detail: "141 open ports on 39 hosts", Duration: 48000},
		{Name: "Name resolution", State: "done", Detail: "Named 41/41 hosts", Duration: 6200},
		{Name: "SNMP polling", State: "done", Detail: "5 SNMP agents polled", Duration: 31000},
		{Name: "Service discovery", State: "done", Detail: "Queried mDNS/Bonjour and SSDP/UPnP", Duration: 4300},
		{Name: "Passive listening", State: "done", Detail: "Listened for DHCP, LLDP/CDP, STP", Duration: 1260000},
		{Name: "Analysis", State: "done", Detail: "", Duration: 300},
	}
	st.UpdateScan(func(s *model.ScanStatus) {
		*s = model.ScanStatus{Phase: "Analysis", Progress: 1, Started: start, Finished: now, Message: "Assessment complete", Phases: phases}
	})
	for _, ev := range []struct {
		sev model.Severity
		src string
		msg string
	}{
		{model.SevInfo, "cdp", "CDP: connected to rdg-core-sw01 port GigabitEthernet1/0/24 (native VLAN 1)"},
		{model.SevInfo, "dhcp", "DHCP server 10.20.0.10 answering (router 10.20.0.1, DNS 10.20.0.10)"},
		{model.SevHigh, "dhcp", "2 different DHCP servers are answering on this segment: possible rogue DHCP server"},
		{model.SevHigh, "snmp", "10.20.0.2 (rdg-core-sw01) answers SNMP community \"public\""},
		{model.SevMedium, "storm", "Elevated broadcast/multicast: 2750 pps (warn ≥ 1000), 31 repeated frames"},
		{model.SevMedium, "stp", "Spanning-tree topology change #4 (a port went up/down or a loop is re-converging)"},
	} {
		st.AddEvent(ev.sev, ev.src, ev.msg, "")
	}

	if *vaultDir != "" {
		// Separate store: the sample session must not pick up vault events
		// or lose its Storm Guard / NetFlow providers.
		vst := store.New()
		vst.SetSite(st.Site())
		ve := engine.New(vst, "v2.0.0", *vaultDir)
		_ = os.Remove(ve.VaultPath())
		if err := ve.VaultCreate("sample passphrase"); err != nil {
			panic(err)
		}
		v := ve.Vault()
		for _, c := range []vault.Cred{
			{Type: vault.TypeWindows, Name: "Domain admin (RIVERSIDE)", Domain: "RIVERSIDE", Username: "svc-octolan", Password: "example-only", Notes: "Provided by office manager; expires after visit"},
			{Type: vault.TypeWindows, Name: "X-ray PC local admin", Username: "Administrator", Password: "example-only", Scope: []string{"10.20.10.21"}},
			{Type: vault.TypeSSH, Name: "Core switches (netadmin)", Username: "netadmin", Password: "example-only", Enable: "example-only", Scope: []string{"10.20.0.2-3"}},
			{Type: vault.TypeSNMP, Name: "SNMP read community", SNMPVersion: "v2c", Community: "example-only"},
		} {
			if _, err := v.Put(c); err != nil {
				panic(err)
			}
		}
		_, _ = v.AddConfig(vault.ConfigBackup{DeviceID: coreID, IP: "10.20.0.2", Name: "rdg-core-sw01", Platform: "cisco-ios",
			Command: "show running-config", Text: coreCfg, SHA256: collect.ConfigHash(coreCfg), Captured: now})
		ve.VaultLock()
		fmt.Println("wrote sample vault", ve.VaultPath())
	}

	if err := os.MkdirAll("docs/sample", 0o755); err != nil {
		panic(err)
	}
	if err := st.Save(out, "v2.0.0"); err != nil {
		panic(err)
	}
	f, s, g := st.Findings()
	fmt.Printf("wrote %s: %d devices, %d findings, score %d (%s)\n", out, len(st.Devices()), len(f), s, g)
}
