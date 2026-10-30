package netflow

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/s835773/OcuLAN/internal/model"
	"github.com/s835773/OcuLAN/internal/store"
)

func newTestCollector() *Collector {
	return &Collector{
		st: store.New(), conv: map[convKey]*conv{}, templates: map[tmplKey][]field{},
		hosts: map[netip.Addr]*model.Talker{}, apps: map[string]*model.Talker{},
		protos: map[string]uint64{}, exporters: map[string]uint64{}, versions: map[string]uint64{},
		errs: map[string]uint64{}, observed: map[netip.Addr]bool{},
	}
}

func TestIPFIXVariableLengthAndTemplateLater(t *testing.T) {
	c := newTestCollector()
	// Data set arriving before its template must be counted, not crash.
	data := []byte{0x01, 0x2c, 0, 8, 1, 2, 3, 4}
	pkt := ipfixMsg(data)
	if err := c.parse(pkt, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if c.errs["data before template (waiting for exporter to resend)"] != 1 {
		t.Fatalf("errs %v", c.errs)
	}
	// Template 300: src(8,4) dst(12,4) appName(96,varlen) bytes(1,4)
	tmpl := []byte{}
	tmpl = binary.BigEndian.AppendUint16(tmpl, 300)
	tmpl = binary.BigEndian.AppendUint16(tmpl, 4)
	for _, f := range [][2]uint16{{8, 4}, {12, 4}, {96, 0xffff}, {1, 4}} {
		tmpl = binary.BigEndian.AppendUint16(tmpl, f[0])
		tmpl = binary.BigEndian.AppendUint16(tmpl, f[1])
	}
	set := append([]byte{0, 2, 0, byte(4 + len(tmpl))}, tmpl...)
	rec := []byte{10, 0, 0, 1, 10, 0, 0, 2, 3, 'w', 'e', 'b', 0, 0, 0x10, 0}
	dset := append([]byte{0x01, 0x2c, 0, byte(4 + len(rec))}, rec...)
	if err := c.parse(ipfixMsg(append(set, dset...)), "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if c.totalF != 1 || c.totalB != 4096 {
		t.Fatalf("flows=%d bytes=%d", c.totalF, c.totalB)
	}
}

func ipfixMsg(body []byte) []byte {
	h := make([]byte, 16)
	binary.BigEndian.PutUint16(h[0:], 10)
	binary.BigEndian.PutUint16(h[2:], uint16(16+len(body)))
	return append(h, body...)
}
