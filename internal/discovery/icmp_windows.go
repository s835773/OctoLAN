//go:build windows

package discovery

import (
	"context"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Windows' IcmpSendEcho needs no administrator rights or drivers.
var (
	iphlp            = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreate   = iphlp.NewProc("IcmpCreateFile")
	procIcmpClose    = iphlp.NewProc("IcmpCloseHandle")
	procIcmpSendEcho = iphlp.NewProc("IcmpSendEcho")
)

type ipOptionInfo struct {
	TTL         uint8
	TOS         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInfo
}

func icmpMode() string {
	if procIcmpCreate.Find() != nil {
		return "tcp-only"
	}
	return "windows-api"
}

func pingSweep(ctx context.Context, targets []netip.Addr, rate int, timeout time.Duration, onReply func(PingResult)) (string, error) {
	if procIcmpCreate.Find() != nil {
		return "tcp-only", ErrNoICMP
	}
	h, _, err := procIcmpCreate.Call()
	if h == 0 || h == ^uintptr(0) {
		return "tcp-only", err
	}
	defer procIcmpClose.Call(h)

	payload := []byte("OcuLAN-ping-0123456789abcdef")
	work := make(chan netip.Addr)
	var wg sync.WaitGroup
	workers := 128
	if workers > len(targets) {
		workers = len(targets)
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reply := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+len(payload)+64)
			for ip := range work {
				for attempt := 0; attempt < 2 && ctx.Err() == nil; attempt++ {
					b := ip.As4()
					dst := *(*uint32)(unsafe.Pointer(&b[0]))
					t0 := time.Now()
					n, _, _ := procIcmpSendEcho.Call(h, uintptr(dst),
						uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), 0,
						uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout.Milliseconds()))
					rtt := time.Since(t0)
					if n == 0 {
						continue
					}
					r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
					if r.Status != 0 || r.Address != dst {
						continue
					}
					if api := time.Duration(r.RoundTripTime) * time.Millisecond; api > 0 && api < rtt {
						rtt = api
					}
					onReply(PingResult{IP: ip, RTT: rtt, TTL: int(r.Options.TTL)})
					break
				}
			}
		}()
	}
	wait := pacer(ctx, rate)
	for _, ip := range targets {
		if !wait() {
			break
		}
		work <- ip
	}
	close(work)
	wg.Wait()
	return "windows-api", ctx.Err()
}
