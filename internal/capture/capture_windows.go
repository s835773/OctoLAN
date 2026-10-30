//go:build windows

package capture

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Npcap is loaded lazily from its install directory so OctoLAN still runs
// (in reduced mode) on machines without it.

var (
	npcapOnce sync.Once
	npcapErr  error
	pcapDLL   *syscall.DLL

	pFindAllDevs, pFreeAllDevs, pOpenLive, pNextEx, pSendPacket, pClose, pGetErr *syscall.Proc
)

const errbufSize = 256

func loadNpcap() error {
	npcapOnce.Do(func() {
		sys, err := windows.GetSystemDirectory()
		if err != nil {
			npcapErr = err
			return
		}
		dir := filepath.Join(sys, "Npcap")
		// wpcap.dll depends on Packet.dll in the same folder.
		_ = windows.SetDllDirectory(dir)
		dll, err := syscall.LoadDLL(filepath.Join(dir, "wpcap.dll"))
		if err != nil {
			// Legacy WinPcap / Npcap in compatibility mode.
			dll, err = syscall.LoadDLL("wpcap.dll")
		}
		if err != nil {
			npcapErr = fmt.Errorf("Npcap not installed (%w)", err)
			return
		}
		pcapDLL = dll
		for name, dst := range map[string]**syscall.Proc{
			"pcap_findalldevs": &pFindAllDevs, "pcap_freealldevs": &pFreeAllDevs,
			"pcap_open_live": &pOpenLive, "pcap_next_ex": &pNextEx,
			"pcap_sendpacket": &pSendPacket, "pcap_close": &pClose, "pcap_geterr": &pGetErr,
		} {
			p, err := dll.FindProc(name)
			if err != nil {
				npcapErr = err
				return
			}
			*dst = p
		}
	})
	return npcapErr
}

// C structs from pcap.h.
type pcapIf struct {
	Next        *pcapIf
	Name        *byte
	Description *byte
	Addresses   *pcapAddr
	Flags       uint32
}

type pcapAddr struct {
	Next      *pcapAddr
	Addr      *rawSockaddr
	Netmask   *rawSockaddr
	Broadaddr *rawSockaddr
	Dstaddr   *rawSockaddr
}

type rawSockaddr struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
}

type pcapPkthdr struct {
	Sec    int32
	Usec   int32
	Caplen uint32
	Len    uint32
}

func cstr(p *byte) string {
	if p == nil {
		return ""
	}
	var b []byte
	for ptr := unsafe.Pointer(p); *(*byte)(ptr) != 0; ptr = unsafe.Add(ptr, 1) {
		b = append(b, *(*byte)(ptr))
	}
	return string(b)
}

// npfDevice maps a Windows interface (by its IPv4 addresses or MAC) to the
// Npcap device name \Device\NPF_{GUID}.
func npfDevice(ifc net.Interface) (string, error) {
	var addrs []net.IP
	if as, err := ifc.Addrs(); err == nil {
		for _, a := range as {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				addrs = append(addrs, ipn.IP.To4())
			}
		}
	}
	var all *pcapIf
	errbuf := make([]byte, errbufSize)
	r, _, _ := pFindAllDevs.Call(uintptr(unsafe.Pointer(&all)), uintptr(unsafe.Pointer(&errbuf[0])))
	if int32(r) != 0 {
		return "", fmt.Errorf("pcap_findalldevs: %s", cstr(&errbuf[0]))
	}
	defer pFreeAllDevs.Call(uintptr(unsafe.Pointer(all)))
	for d := all; d != nil; d = d.Next {
		for a := d.Addresses; a != nil; a = a.Next {
			if a.Addr == nil || a.Addr.Family != syscall.AF_INET {
				continue
			}
			ip := net.IP(a.Addr.Addr[:])
			for _, mine := range addrs {
				if mine.Equal(ip) {
					return cstr(d.Name), nil
				}
			}
		}
	}
	return "", fmt.Errorf("no Npcap device matches %s", ifc.Name)
}

type npcapHandle struct {
	p      uintptr
	mu     sync.Mutex
	closed bool
}

func open(ifc net.Interface, promisc bool) (Handle, error) {
	if err := loadNpcap(); err != nil {
		return nil, err
	}
	dev, err := npfDevice(ifc)
	if err != nil {
		return nil, err
	}
	name, _ := syscall.BytePtrFromString(dev)
	errbuf := make([]byte, errbufSize)
	pr := 0
	if promisc {
		pr = 1
	}
	p, _, _ := pOpenLive.Call(uintptr(unsafe.Pointer(name)), 65536, uintptr(pr), 250, uintptr(unsafe.Pointer(&errbuf[0])))
	if p == 0 {
		return nil, fmt.Errorf("pcap_open_live: %s", cstr(&errbuf[0]))
	}
	return &npcapHandle{p: p}, nil
}

func (h *npcapHandle) ReadPacket() ([]byte, time.Time, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, time.Time{}, net.ErrClosed
	}
	var hdr *pcapPkthdr
	var data *byte
	r, _, _ := pNextEx.Call(h.p, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data)))
	switch int32(r) {
	case 1:
		n := int(hdr.Caplen)
		out := make([]byte, n)
		copy(out, unsafe.Slice(data, n))
		return out, time.Unix(int64(hdr.Sec), int64(hdr.Usec)*1000), nil
	case 0:
		return nil, time.Time{}, ErrTimeout
	default:
		e, _, _ := pGetErr.Call(h.p)
		return nil, time.Time{}, errors.New(cstr(*(**byte)(unsafe.Pointer(&e))))
	}
}

func (h *npcapHandle) WritePacket(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	r, _, _ := pSendPacket.Call(h.p, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if int32(r) != 0 {
		e, _, _ := pGetErr.Call(h.p)
		return errors.New(cstr(*(**byte)(unsafe.Pointer(&e))))
	}
	return nil
}

func (h *npcapHandle) Close() error {
	// Wait for an in-flight read (bounded by the 250ms timeout).
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.closed {
		h.closed = true
		pClose.Call(h.p)
	}
	return nil
}

func explain(err error) string {
	if npcapErr != nil {
		return "install the free Npcap driver (https://npcap.com) to enable ARP sweeps, passive listening and Storm Guard; everything else works without it"
	}
	return err.Error()
}
