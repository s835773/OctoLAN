//go:build linux

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/sys/unix"
)

type linuxHandle struct {
	rd    *pcapgo.EthernetHandle
	wfd   int
	ifidx int
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func open(ifc net.Interface, promisc bool) (Handle, error) {
	rd, err := pcapgo.NewEthernetHandle(ifc.Name)
	if err != nil {
		return nil, err
	}
	_ = rd.SetCaptureLength(65536)
	if promisc {
		_ = rd.SetPromiscuous(true)
	}
	wfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		rd.Close()
		return nil, err
	}
	if err := unix.Bind(wfd, &unix.SockaddrLinklayer{Ifindex: ifc.Index}); err != nil {
		rd.Close()
		unix.Close(wfd)
		return nil, err
	}
	return &linuxHandle{rd: rd, wfd: wfd, ifidx: ifc.Index}, nil
}

func (h *linuxHandle) ReadPacket() ([]byte, time.Time, error) {
	data, ci, err := h.rd.ReadPacketData()
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, time.Time{}, ErrTimeout
		}
		return nil, time.Time{}, err
	}
	// The kernel strips 802.1Q tags into ancillary data; put them back so
	// VLAN discovery sees the frame as it was on the wire.
	if len(ci.AncillaryData) > 0 && len(data) >= 12 {
		if tci, ok := ci.AncillaryData[0].(int); ok {
			tagged := make([]byte, len(data)+4)
			copy(tagged, data[:12])
			binary.BigEndian.PutUint16(tagged[12:], 0x8100)
			binary.BigEndian.PutUint16(tagged[14:], uint16(tci))
			copy(tagged[16:], data[12:])
			data = tagged
		}
	}
	return data, ci.Timestamp, nil
}

func (h *linuxHandle) WritePacket(b []byte) error {
	if len(b) < 14 {
		return fmt.Errorf("frame too short")
	}
	sa := &unix.SockaddrLinklayer{Ifindex: h.ifidx, Protocol: htons(binary.BigEndian.Uint16(b[12:14])), Halen: 6}
	copy(sa.Addr[:], b[:6])
	return unix.Sendto(h.wfd, b, 0, sa)
}

func (h *linuxHandle) Close() error {
	unix.Close(h.wfd)
	return h.rd.Close()
}

func explain(err error) string {
	s := err.Error()
	if strings.Contains(s, "operation not permitted") || strings.Contains(s, "permission") {
		return "raw sockets need root: run with sudo, or grant once with `sudo setcap cap_net_raw,cap_net_admin+ep ./oculan`"
	}
	return s
}
