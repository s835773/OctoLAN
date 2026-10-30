package collect

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/s835773/OctoLAN/internal/model"
	"github.com/s835773/OctoLAN/internal/vault"
)

func TestScope(t *testing.T) {
	s := NewScoper([]netip.Addr{netip.MustParseAddr("10.0.0.5")})
	def := vault.Cred{ID: "a"}
	if !s.Allows(def, netip.MustParseAddr("10.0.0.5")) || s.Allows(def, netip.MustParseAddr("10.0.0.6")) {
		t.Error("default scope should be the scan targets")
	}
	scoped := vault.Cred{ID: "b", Scope: []string{"192.168.1.0/24"}}
	if !s.Allows(scoped, netip.MustParseAddr("192.168.1.9")) || s.Allows(scoped, netip.MustParseAddr("10.0.0.5")) {
		t.Error("explicit scope not honoured")
	}
}

func TestDomainMatches(t *testing.T) {
	acme := vault.Cred{Domain: "ACME", Username: "admin"}
	inDomain := &model.Device{SMB: &model.SMBInfo{DNSDomain: "acme.local"}}
	otherDomain := &model.Device{SMB: &model.SMBInfo{DNSDomain: "evil.corp"}}
	unknown := &model.Device{}
	if !DomainMatches(acme, inDomain) {
		t.Error("ACME cred should go to acme.local hosts")
	}
	if DomainMatches(acme, otherDomain) {
		t.Error("domain cred must not be sent to a foreign-domain host")
	}
	if DomainMatches(acme, unknown) {
		t.Error("unscoped domain cred must not go to hosts of unknown domain")
	}
	acme.Scope = []string{"10.0.0.9"}
	if !DomainMatches(acme, unknown) {
		t.Error("explicitly scoped cred may go to unknown-domain host")
	}
	if !DomainMatches(vault.Cred{Username: "Administrator"}, otherDomain) {
		t.Error("local accounts aren't domain-restricted")
	}
}

func TestGuard(t *testing.T) {
	g := NewGuard(2)
	auth := errors.New("http response error: 401 - invalid content type")
	if g.Result("c", errors.New("dial tcp: i/o timeout")) || !g.Allowed("c") {
		t.Error("timeouts must not count toward lockout")
	}
	g.Result("c", auth)
	if !g.Allowed("c") {
		t.Error("disabled too early")
	}
	if !g.Result("c", auth) || g.Allowed("c") {
		t.Error("should disable after 2 rejections")
	}
}

func TestParseWindows(t *testing.T) {
	sys := `{"os":"Microsoft Windows Server 2019 Standard","ver":"10.0.17763","build":"17763","ubr":6054,"disp":"1809","inst":"2021-03-04T10:00:00.0000000Z","boot":"2026-10-01T02:00:00.0000000Z","mfr":"Dell Inc.","model":"PowerEdge R640","serial":"ABC123","domain":"acme.local","joined":true,"ram":64,"cpu":"Intel Xeon","hfn":42,"hf":"2026-06-10T00:00:00.0000000Z","hfid":"KB5039217","rtp":false,"av":true,"sig":12,"avp":[],"fw":[{"n":"Domain","e":true},{"n":"Public","e":false}],"bl":[{"d":"C:","p":0}],"disk":[{"d":"C:","s":100,"f":4.5}],"reboot":true,"smb1":false,"nla":true,"autologon":false}`
	acct := `{"admins":["ACME\\Domain Admins","FS01\\Administrator","ACME\\jsmith"],"users":[{"n":"Administrator","e":true,"p":"2020-01-01T00:00:00.0000000Z"}],"swn":2,"sw":[{"n":"7-Zip","v":"19.00","p":"Igor Pavlov"},{"n":"Veeam Agent","v":"6.0","p":"Veeam"}]}`
	w, err := ParseWindows(sys, acct)
	if err != nil {
		t.Fatal(err)
	}
	if w.Build != "17763" || w.HotfixCount != 42 || w.LastHotfix.Year() != 2026 || *w.DefenderRTP || w.Firewall["Public"] ||
		w.BitLocker[0].Protected || !w.PendingReboot || len(w.Admins) != 3 || w.SoftwareCount != 2 || w.Software[1].Name != "Veeam Agent" {
		t.Fatalf("parsed %+v", w)
	}
}

func TestAuditCiscoConfig(t *testing.T) {
	cfg := `hostname core
enable password cisco123
snmp-server community public RO
snmp-server community private RW
ip http server
username admin privilege 15 password 0 hunter2
line vty 0 4
 transport input telnet ssh
end`
	got := AuditConfig(PlatCiscoIOS, cfg)
	for _, want := range []string{IssueEnablePassword, IssueNoPwEncryption, IssueTelnetVTY, IssueHTTPServer, IssueSNMPWrite, IssueNoSyslog, IssueNoNTP, IssueWeakLocalUser, IssueNoAAA} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	clean := `hostname core
service password-encryption
aaa new-model
enable secret 9 $9$abc
no ip http server
logging host 10.0.0.50
ntp server 10.0.0.1
line vty 0 4
 transport input ssh
end`
	if got := AuditConfig(PlatCiscoIOS, clean); len(got) != 0 {
		t.Errorf("clean config flagged: %v", got)
	}
}

func TestPlatformDetection(t *testing.T) {
	if p := platformFromVersion("Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E4"); p != PlatCiscoIOS {
		t.Error(p)
	}
	n := parseShowVersion(PlatCiscoIOS, "Cisco IOS Software, Version 15.2(7)E4, RELEASE\nrouter uptime is 3 weeks, 2 days\ncisco WS-C2960X-48FPD-L (APM86XXX) processor\nSystem serial number            : FOC2138X0AB\n")
	if n.Version != "15.2(7)E4" || n.Model != "WS-C2960X-48FPD-L" || n.Serial != "FOC2138X0AB" || n.Uptime != "3 weeks, 2 days" {
		t.Errorf("parsed %+v", n)
	}
	d := &model.Device{Vendor: "Fortinet, Inc.", Type: model.TypeFirewall}
	if GuessPlatform(d) != PlatFortiOS {
		t.Error("fortinet")
	}
}
