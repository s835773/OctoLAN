package topology

import (
	"testing"

	"github.com/s835773/OctoLAN/internal/model"
)

func TestBuild(t *testing.T) {
	gw := &model.Device{ID: "aa:00:00:00:00:01", MAC: "aa:00:00:00:00:01", IPs: []string{"10.0.0.1"}, Type: model.TypeFirewall, IsGateway: true}
	core := &model.Device{ID: "aa:00:00:00:00:02", MAC: "aa:00:00:00:00:02", IPs: []string{"10.0.0.2"}, Type: model.TypeSwitch,
		Neighbors: []model.Neighbor{{Protocol: "lldp", LocalPort: "Gi1/0/48", RemoteChassis: "aa:00:00:00:00:01", RemotePort: "port1"}},
		FDB: []model.FDBEntry{
			{MAC: "bb:00:00:00:00:01", Port: "Gi1/0/1"},
			{MAC: "bb:00:00:00:00:02", Port: "Gi1/0/2"},
			{MAC: "aa:00:00:00:00:01", Port: "Gi1/0/48"},
		}}
	pc1 := &model.Device{ID: "bb:00:00:00:00:01", MAC: "bb:00:00:00:00:01", IPs: []string{"10.0.0.10"}, Type: model.TypeWorkstation}
	pc2 := &model.Device{ID: "bb:00:00:00:00:02", MAC: "bb:00:00:00:00:02", IPs: []string{"10.0.0.11"}, Type: model.TypeWorkstation}
	stray := &model.Device{ID: "ip-10.0.0.99", IPs: []string{"10.0.0.99"}, Type: model.TypeUnknown}
	links := Build([]*model.Device{gw, core, pc1, pc2, stray}, []model.Subnet{{CIDR: "10.0.0.0/24", Gateway: "10.0.0.1"}})

	find := func(a, b string) *model.Link {
		for i := range links {
			l := &links[i]
			if (l.A == a && l.B == b) || (l.A == b && l.B == a) {
				return l
			}
		}
		return nil
	}
	if l := find(core.ID, gw.ID); l == nil || l.Kind != "lldp" {
		t.Errorf("core-gw lldp link missing: %+v", links)
	}
	if l := find(core.ID, pc1.ID); l == nil || l.Kind != "fdb" {
		t.Errorf("pc1 not placed on switch port: %+v", links)
	}
	if l := find("net:10.0.0.0/24", stray.ID); l == nil {
		t.Errorf("stray not attached to subnet cloud: %+v", links)
	}
	if l := find(gw.ID, "net:10.0.0.0/24"); l == nil {
		t.Errorf("subnet cloud not attached to gateway: %+v", links)
	}
}
