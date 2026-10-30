package netutil

import (
	"net/netip"
	"testing"
)

func TestParseTargets(t *testing.T) {
	cases := []struct {
		in      []string
		want    int
		first   string
		last    string
		wantErr bool
	}{
		{[]string{"192.168.1.0/24"}, 254, "192.168.1.1", "192.168.1.254", false},
		{[]string{"10.0.0.5"}, 1, "10.0.0.5", "10.0.0.5", false},
		{[]string{"10.0.0.10-20"}, 11, "10.0.0.10", "10.0.0.20", false},
		{[]string{"10.0.0.250-10.0.1.5"}, 12, "10.0.0.250", "10.0.1.5", false},
		{[]string{"10.0.0.1, 10.0.0.1 10.0.0.2"}, 2, "10.0.0.1", "10.0.0.2", false},
		{[]string{"10.0.0.0/31"}, 2, "10.0.0.0", "10.0.0.1", false},
		{[]string{"10.0.0.0/8"}, 0, "", "", true},
		{[]string{"10.0.0.20-10"}, 0, "", "", true},
		{[]string{"not an ip!"}, 0, "", "", true},
	}
	for _, c := range cases {
		got, err := ParseTargets(c.in)
		if (err != nil) != c.wantErr {
			t.Fatalf("%v: err=%v wantErr=%v", c.in, err, c.wantErr)
		}
		if c.wantErr {
			continue
		}
		if len(got) != c.want || got[0].String() != c.first || got[len(got)-1].String() != c.last {
			t.Errorf("%v: got %d [%s..%s], want %d [%s..%s]", c.in, len(got), got[0], got[len(got)-1], c.want, c.first, c.last)
		}
	}
}

func TestScanPrefixFor(t *testing.T) {
	l := LocalIface{Addr: netip.MustParseAddr("10.20.30.40"), Prefix: netip.MustParsePrefix("10.20.0.0/16")}
	if got := ScanPrefixFor(l).String(); got != "10.20.28.0/22" {
		t.Fatalf("got %s", got)
	}
}

func TestParseBSDARP(t *testing.T) {
	out := []byte(`? (192.168.1.1) at 0:11:22:a:b:c on en0 ifscope [ethernet]
? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]`)
	got := parseBSDARP(out)
	if len(got) != 1 || got[0].MAC.String() != "00:11:22:0a:0b:0c" || got[0].Iface != "en0" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseWindowsRoute(t *testing.T) {
	out := []byte(`Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     35
          0.0.0.0          0.0.0.0         10.0.0.1       10.0.0.7     25`)
	gw, err := parseWindowsRoute(out)
	if err != nil || gw.String() != "10.0.0.1" {
		t.Fatalf("got %v %v", gw, err)
	}
}
