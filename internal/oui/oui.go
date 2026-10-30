// Package oui maps MAC addresses to hardware vendors using an embedded
// copy of the IEEE registry (regenerate with tools/genoui).
package oui

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"net"
	"strings"
	"sync"
)

//go:embed oui.txt.gz
var raw []byte

var (
	once sync.Once
	// tables keyed by prefix length in hex digits (6, 7, 9).
	tables = map[int]map[string]string{}
)

func load() {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		prefix, name, ok := strings.Cut(sc.Text(), "\t")
		if !ok {
			continue
		}
		hex, _, _ := strings.Cut(prefix, "/")
		t := tables[len(hex)]
		if t == nil {
			t = map[string]string{}
			tables[len(hex)] = t
		}
		t[hex] = name
	}
}

// Lookup returns the vendor for a MAC address, or "" if unknown.
func Lookup(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}
	once.Do(load)
	hex := strings.ToUpper(strings.ReplaceAll(mac.String(), ":", ""))
	// Longest (most specific) allocation wins.
	for _, n := range []int{9, 7, 6} {
		if len(hex) >= n {
			if v, ok := tables[n][hex[:n]]; ok {
				return v
			}
		}
	}
	return ""
}

// LookupString parses s as a MAC address and looks it up.
func LookupString(s string) string {
	mac, err := net.ParseMAC(s)
	if err != nil {
		return ""
	}
	return Lookup(mac)
}

// IsLocallyAdministered reports whether the MAC is randomized/locally
// assigned (common for phones using private Wi-Fi addresses).
func IsLocallyAdministered(mac net.HardwareAddr) bool {
	return len(mac) > 0 && mac[0]&0x02 != 0
}
