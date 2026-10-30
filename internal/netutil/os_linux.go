//go:build linux

package netutil

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
)

func linuxGateway() (netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(fields[2])
		if err != nil || len(b) != 4 {
			continue
		}
		v := binary.LittleEndian.Uint32(b)
		if v == 0 {
			continue
		}
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], v)
		return netip.AddrFrom4(out), nil
	}
	return netip.Addr{}, ErrNoGateway
}

func linuxARP() ([]ARPEntry, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var res []ARPEntry
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 || f[2] == "0x0" { // incomplete
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		mac, err := parseLooseMAC(f[3])
		if err != nil {
			continue
		}
		res = append(res, ARPEntry{IP: ip, MAC: mac, Iface: f[5]})
	}
	return res, nil
}

func windowsARP() ([]ARPEntry, error) { return nil, nil }

// SendARP is only implemented on Windows.
func SendARP(netip.Addr) (net.HardwareAddr, error) { return nil, errors.New("unsupported") }
