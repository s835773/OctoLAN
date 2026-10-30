package assess

import (
	"testing"
	"time"

	"github.com/s835773/OctoLAN/internal/model"
)

func TestRun(t *testing.T) {
	now := time.Now()
	devs := []*model.Device{
		{ID: "sw", Type: model.TypeSwitch, Alive: true, Ports: []model.Port{{Port: 23}, {Port: 80}},
			SNMP: &model.SNMPInfo{Version: "v2c", DefaultComm: true, SysName: "core"}},
		{ID: "fs", Type: model.TypeServer, Alive: true, SMB: &model.SMBInfo{SMB1: true}, OS: model.OSGuess{EOL: true},
			TLS: []model.TLSInfo{{Port: 443, NotAfter: now.Add(-24 * time.Hour)}}},
		{ID: "pc", Type: model.TypeWorkstation, Alive: true},
	}
	finds, score, grade := Run(Input{Devices: devs, Now: now,
		DHCPServers: []model.DHCPServer{{IP: "10.0.0.1"}, {IP: "10.0.0.66"}}})
	want := map[string]bool{"telnet": false, "snmp-default-community": false, "smbv1": false, "eol-os": false,
		"tls-expired": false, "rogue-dhcp": false, "http-mgmt": false, "smb-signing": false}
	for _, f := range finds {
		if _, ok := want[f.Check]; ok {
			want[f.Check] = true
		}
	}
	for k, v := range want {
		if !v {
			t.Errorf("missing finding %s", k)
		}
	}
	if score >= 60 || grade == "A" {
		t.Errorf("score too generous: %d %s", score, grade)
	}
	if finds[0].Severity != model.SevHigh && finds[0].Severity != model.SevCritical {
		t.Errorf("findings not sorted by severity: %v", finds[0].Severity)
	}

	clean, s2, g2 := Run(Input{Devices: []*model.Device{{ID: "x", Type: model.TypeWorkstation, Alive: true}}, Now: now})
	if s2 != 100 || g2 != "A" || len(clean) != 0 {
		t.Errorf("clean network: %d %s %v", s2, g2, clean)
	}
}
