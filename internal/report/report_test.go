package report

import "testing"

func TestShortVendor(t *testing.T) {
	for in, want := range map[string]string{
		"Yealink(Xiamen) Network Technology Co.,Ltd.":    "Yealink",
		"Lenovo Mobile Communication Technology Ltd.":    "Lenovo",
		"Cisco Systems, Inc":                             "Cisco",
		"Apple, Inc.":                                    "Apple",
		"Hangzhou Hikvision Digital Technology Co.,Ltd.": "Hangzhou Hikvision Digital",
		"Dell Inc.": "Dell",
	} {
		if got := ShortVendor(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}
