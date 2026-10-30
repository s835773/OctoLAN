//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package capture

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const isDarwin = runtime.GOOS == "darwin"

type bpfHandle struct {
	fd     int
	buf    []byte
	n, off int
	mu     sync.Mutex
	closed bool
}

func open(ifc net.Interface, promisc bool) (Handle, error) {
	var fd = -1
	var lastErr error
	if f, err := unix.Open("/dev/bpf", unix.O_RDWR|unix.O_CLOEXEC, 0); err == nil { // cloning device (FreeBSD)
		fd = f
	} else {
		for i := 0; i < 256; i++ {
			f, err := unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR|unix.O_CLOEXEC, 0)
			if err == nil {
				fd = f
				break
			}
			lastErr = err
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
				break
			}
		}
	}
	if fd < 0 {
		if lastErr == nil {
			lastErr = errors.New("no bpf device available")
		}
		return nil, lastErr
	}
	fail := func(err error) (Handle, error) {
		unix.Close(fd)
		return nil, err
	}
	bufLen, err := syscall.SetBpfBuflen(fd, 1<<20)
	if err != nil {
		if bufLen, err = syscall.BpfBuflen(fd); err != nil {
			return fail(err)
		}
	}
	if err := syscall.SetBpfInterface(fd, ifc.Name); err != nil {
		return fail(fmt.Errorf("bind %s: %w", ifc.Name, err))
	}
	if err := syscall.SetBpfImmediate(fd, 1); err != nil {
		return fail(err)
	}
	tv := syscall.Timeval{Usec: 250000}
	if err := syscall.SetBpfTimeout(fd, &tv); err != nil {
		return fail(err)
	}
	_ = syscall.SetBpfHeadercmpl(fd, 1) // we supply our own source MAC
	if promisc {
		_ = syscall.SetBpfPromisc(fd, 1)
	}
	return &bpfHandle{fd: fd, buf: make([]byte, bufLen)}, nil
}

func wordAlign(x int) int {
	const w = int(unsafe.Sizeof(uintptr(0)))
	if w == 8 && isDarwin {
		// macOS aligns BPF records to 4 bytes (BPF_ALIGNMENT is sizeof(int32)).
		return (x + 3) &^ 3
	}
	return (x + w - 1) &^ (w - 1)
}

func (h *bpfHandle) ReadPacket() ([]byte, time.Time, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, time.Time{}, net.ErrClosed
	}
	if h.off >= h.n {
		n, err := unix.Read(h.fd, h.buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				return nil, time.Time{}, ErrTimeout
			}
			return nil, time.Time{}, err
		}
		if n == 0 {
			return nil, time.Time{}, ErrTimeout
		}
		h.n, h.off = n, 0
	}
	if h.off+int(unsafe.Sizeof(unix.BpfHdr{})) > h.n {
		h.off = h.n
		return nil, time.Time{}, ErrTimeout
	}
	hdr := (*unix.BpfHdr)(unsafe.Pointer(&h.buf[h.off]))
	start := h.off + int(hdr.Hdrlen)
	end := start + int(hdr.Caplen)
	h.off += wordAlign(int(hdr.Hdrlen) + int(hdr.Caplen))
	if end > h.n || start > end {
		h.off = h.n
		return nil, time.Time{}, errors.New("corrupt bpf record")
	}
	out := make([]byte, end-start)
	copy(out, h.buf[start:end])
	return out, time.Unix(int64(hdr.Tstamp.Sec), int64(hdr.Tstamp.Usec)*1000), nil
}

func (h *bpfHandle) WritePacket(b []byte) error {
	_, err := unix.Write(h.fd, b)
	return err
}

func (h *bpfHandle) Close() error {
	h.closed = true
	return unix.Close(h.fd)
}

func explain(err error) string {
	if errors.Is(err, os.ErrPermission) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) ||
		strings.Contains(err.Error(), "permission") {
		return "BPF devices need root: run with sudo (or install Wireshark's ChmodBPF helper)"
	}
	return err.Error()
}
