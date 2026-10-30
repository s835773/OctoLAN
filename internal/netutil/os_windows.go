//go:build windows

package netutil

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"
)

var (
	iphlpapi        = syscall.NewLazyDLL("iphlpapi.dll")
	procGetIpNetTbl = iphlpapi.NewProc("GetIpNetTable")
	procSendARP     = iphlpapi.NewProc("SendARP")
)

func linuxGateway() (netip.Addr, error) { return netip.Addr{}, ErrNoGateway }
func linuxARP() ([]ARPEntry, error)     { return nil, nil }

// MIB_IPNETROW
type ipNetRow struct {
	Index       uint32
	PhysAddrLen uint32
	PhysAddr    [8]byte
	Addr        [4]byte
	Type        uint32 // 2=invalid 3=dynamic 4=static
}

func windowsARP() ([]ARPEntry, error) {
	var size uint32
	procGetIpNetTbl.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	r, _, _ := procGetIpNetTbl.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1)
	if r != 0 {
		return nil, fmt.Errorf("GetIpNetTable: error %d", r)
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(ipNetRow{})
	var res []ARPEntry
	ifNames := map[int]string{}
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			ifNames[i.Index] = i.Name
		}
	}
	for i := uint32(0); i < n; i++ {
		off := 4 + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*ipNetRow)(unsafe.Pointer(&buf[off]))
		if row.Type == 2 || row.PhysAddrLen != 6 {
			continue
		}
		mac := net.HardwareAddr(append([]byte(nil), row.PhysAddr[:6]...))
		if mac[0]&1 == 1 {
			continue
		}
		res = append(res, ARPEntry{IP: netip.AddrFrom4(row.Addr), MAC: mac, Iface: ifNames[int(row.Index)]})
	}
	return res, nil
}

// SendARP asks Windows to resolve ip on the local segment. It works without
// Npcap or administrator rights.
func SendARP(ip netip.Addr) (net.HardwareAddr, error) {
	b := ip.As4()
	dst := *(*uint32)(unsafe.Pointer(&b[0]))
	var mac [8]byte
	l := uint32(len(mac))
	r, _, _ := procSendARP.Call(uintptr(dst), 0, uintptr(unsafe.Pointer(&mac[0])), uintptr(unsafe.Pointer(&l)))
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	if l < 6 {
		return nil, fmt.Errorf("short mac")
	}
	return net.HardwareAddr(append([]byte(nil), mac[:6]...)), nil
}
