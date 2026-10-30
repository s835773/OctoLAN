package store

import (
	"testing"

	"github.com/s835773/OctoLAN/internal/model"
)

func TestObserveMergesIPOnlyIntoMAC(t *testing.T) {
	s := New()
	s.Observe("10.0.0.5", "", model.SrcICMP, func(d *model.Device) { d.RTTMicro = 900 })
	s.Observe("10.0.0.5", "00:11:22:33:44:55", model.SrcARP, nil)
	devs := s.Devices()
	if len(devs) != 1 {
		t.Fatalf("want 1 device, got %d", len(devs))
	}
	d := devs[0]
	if d.MAC != "00:11:22:33:44:55" || d.RTTMicro != 900 || len(d.Sources) != 2 {
		t.Fatalf("bad merge: %+v", d)
	}
	if d.Vendor == "" {
		t.Errorf("vendor lookup failed for Cisco-range... got empty (OUI 00:11:22 is CIMSYS)")
	}
}

func TestDuplicateIPDetection(t *testing.T) {
	s := New()
	s.Observe("10.0.0.7", "00:00:00:00:00:01", model.SrcARP, nil)
	s.Observe("10.0.0.7", "00:00:00:00:00:02", model.SrcARP, nil)
	s.Observe("10.0.0.7", "00:00:00:00:00:01", model.SrcARP, nil)
	if d := s.DuplicateIPs(); len(d["10.0.0.7"]) != 2 {
		t.Fatalf("expected duplicate, got %v", d)
	}
}

func TestIgnoresMulticastMAC(t *testing.T) {
	s := New()
	s.Observe("10.0.0.9", "01:00:5e:00:00:fb", model.SrcPassive, nil)
	if d := s.Devices(); len(d) != 1 || d[0].MAC != "" {
		t.Fatalf("multicast MAC should be dropped: %+v", d)
	}
}

func TestSnapshotStripsSecrets(t *testing.T) {
	s := New()
	s.UpdateScan(func(st *model.ScanStatus) {
		st.Config = &model.ScanConfig{Communities: []string{"s3cret"}, SNMPv3: []model.SNMPv3Cred{{User: "u", AuthPass: "p"}}}
	})
	s.Observe("10.0.0.1", "", model.SrcSNMP, func(d *model.Device) {
		d.SNMP = &model.SNMPInfo{Community: "s3cret", Version: "v2c"}
	})
	snap := s.Snapshot("test")
	if snap.Scan.Config.Communities != nil || snap.Scan.Config.SNMPv3 != nil {
		t.Fatal("scan config secrets leaked")
	}
	if snap.Devices[0].SNMP.Community != "s3cret" {
		// in-memory copy keeps it (needed for re-polling) but JSON must not
	}
	b, _ := jsonMarshal(snap)
	if contains(b, "s3cret") {
		t.Fatal("community string serialized")
	}
}
