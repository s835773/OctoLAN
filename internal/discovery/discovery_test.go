package discovery

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/s835773/OctoLAN/internal/model"
)

func TestParseSynAck(t *testing.T) {
	f := make([]byte, 14+20+24)
	binary.BigEndian.PutUint16(f[12:], 0x0800)
	ip := f[14:]
	ip[0] = 0x45
	ip[6] = 0x40 // DF
	ip[8] = 127  // TTL
	ip[9] = 6
	copy(ip[12:16], net.IPv4(192, 168, 1, 20).To4())
	tcp := ip[20:]
	tcp[12] = 6 << 4 // 24-byte header
	tcp[13] = 0x12   // SYN+ACK
	binary.BigEndian.PutUint16(tcp[14:], 64240)
	copy(tcp[20:], []byte{2, 4, 0x05, 0xb4}) // MSS 1460
	addr, tr, ok := parseSynAck(f)
	if !ok || addr.String() != "192.168.1.20" || tr.TTL != 127 || !tr.DF || tr.Window != 64240 || tr.MSS != 1460 {
		t.Fatalf("got %v %+v %v", addr, tr, ok)
	}
	if NormTTL(tr.TTL) != 128 {
		t.Fatal("NormTTL")
	}
}

func TestParseARPReply(t *testing.T) {
	f := arpRequest(net.HardwareAddr{2, 0, 0, 0, 0, 1}, mustAddr("10.0.0.5"), mustAddr("10.0.0.9"))
	ip, mac, ok := parseARPReply(f)
	if !ok || ip.String() != "10.0.0.5" || mac.String() != "02:00:00:00:00:01" {
		t.Fatalf("got %v %v %v", ip, mac, ok)
	}
}

func TestNTLMChallenge(t *testing.T) {
	// Build a minimal CHALLENGE with version 10.0.20348 and AV pairs.
	ti := []byte{}
	av := func(id uint16, s string) {
		u := utf16Bytes(s)
		ti = binary.LittleEndian.AppendUint16(ti, id)
		ti = binary.LittleEndian.AppendUint16(ti, uint16(len(u)))
		ti = append(ti, u...)
	}
	av(1, "FS01")
	av(2, "CONTOSO")
	av(3, "fs01.contoso.local")
	av(4, "contoso.local")
	ti = append(ti, 0, 0, 0, 0)
	m := make([]byte, 56)
	copy(m, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(m[8:], 2)
	binary.LittleEndian.PutUint32(m[20:], 0x02000000)
	binary.LittleEndian.PutUint16(m[40:], uint16(len(ti)))
	binary.LittleEndian.PutUint32(m[44:], 56)
	m[48], m[49] = 10, 0
	binary.LittleEndian.PutUint16(m[50:], 20348)
	m = append(m, ti...)
	var info model.SMBInfo
	parseNTLMChallenge(m, &info)
	if info.NetBIOSName != "FS01" || info.DNSDomain != "contoso.local" || info.OSBuild != "20348" || info.OSMajorMinor != "10.0" {
		t.Fatalf("got %+v", info)
	}
	name, eol := WindowsVersion(info.OSMajorMinor, info.OSBuild, true)
	if name != "Windows Server 2022" || eol {
		t.Fatalf("got %s %v", name, eol)
	}
}

func utf16Bytes(s string) []byte {
	var b []byte
	for _, r := range s {
		b = binary.LittleEndian.AppendUint16(b, uint16(r))
	}
	return b
}

func TestWindowsVersion(t *testing.T) {
	cases := []struct {
		mm, build string
		server    bool
		name      string
		eol       bool
	}{
		{"6.1", "7601", false, "Windows 7", true},
		{"6.3", "9600", true, "Windows Server 2012 R2", true},
		{"10.0", "19045", false, "Windows 10 22H2", true},
		{"10.0", "26100", false, "Windows 11 24H2", false},
		{"10.0", "26100", true, "Windows Server 2025", false},
		{"10.0", "17763", true, "Windows Server 2019", false},
	}
	for _, c := range cases {
		n, e := WindowsVersion(c.mm, c.build, c.server)
		if n != c.name || e != c.eol {
			t.Errorf("%s.%s server=%v: got %q eol=%v", c.mm, c.build, c.server, n, e)
		}
	}
}

func TestParsePorts(t *testing.T) {
	p, err := ParsePorts("22, 80,8000-8002")
	if err != nil || len(p) != 5 || p[0] != 22 || p[4] != 8002 {
		t.Fatalf("got %v %v", p, err)
	}
	if _, err := ParsePorts("70000"); err == nil {
		t.Fatal("expected error")
	}
	if p, _ := ParsePorts("default"); len(p) != len(DefaultPorts) {
		t.Fatal("default")
	}
}

func TestClassify(t *testing.T) {
	printer := &model.Device{Type: model.TypeUnknown, Ports: []model.Port{{Port: 9100}, {Port: 80}}}
	Classify(printer)
	if printer.Type != model.TypePrinter {
		t.Errorf("printer: %s", printer.Type)
	}
	sw := &model.Device{Type: model.TypeUnknown, SNMP: &model.SNMPInfo{SysDescr: "Cisco IOS Software, C2960X Software", SysServices: 2}}
	Classify(sw)
	if sw.Type != model.TypeSwitch || sw.OS.Family != "Cisco IOS" {
		t.Errorf("switch: %s %s", sw.Type, sw.OS.Family)
	}
	mac := &model.Device{Type: model.TypeUnknown, Model: "Mac15,6", Vendor: "Apple, Inc."}
	Classify(mac)
	if mac.Type != model.TypeWorkstation || mac.OS.Family != "macOS" {
		t.Errorf("mac: %s %s", mac.Type, mac.OS.Family)
	}
	self := &model.Device{Type: model.TypeWorkstation, IsSelf: true, Services: []model.Service{{Type: "_airplay._tcp"}}}
	Classify(self)
	if self.Type != model.TypeWorkstation {
		t.Errorf("self reclassified as %s", self.Type)
	}
	win := &model.Device{Type: model.TypeUnknown, Ports: []model.Port{{Port: 445}, {Port: 135}, {Port: 3389}},
		SMB: &model.SMBInfo{OSMajorMinor: "6.1", OSBuild: "7601"}}
	Classify(win)
	if win.Type != model.TypeWorkstation || !win.OS.EOL || win.OS.Family != "Windows" {
		t.Errorf("win7: %s %+v", win.Type, win.OS)
	}
}

func TestServerName(t *testing.T) {
	for _, h := range []string{"RDG-FS01", "dc02.contoso.local", "sql-prod", "SRV-APP1", "hv3", "acme_veeam01"} {
		if !serverName(h) {
			t.Errorf("%s should look like a server", h)
		}
	}
	for _, h := range []string{"RDG-WS04", "Dr-Patel-MacBook", "desktop-7h2k", "printer-front", "fsmith-laptop", ""} {
		if serverName(h) {
			t.Errorf("%s should not look like a server", h)
		}
	}
}
