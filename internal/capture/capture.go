// Package capture gives OcuLAN raw Ethernet send/receive on every OS
// without cgo or external libraries:
//
//   - Linux:   AF_PACKET sockets (root or CAP_NET_RAW)
//   - macOS:   /dev/bpf devices (root, or Wireshark's ChmodBPF helper)
//   - Windows: Npcap's wpcap.dll, loaded at runtime only if installed
//
// A Hub shares one capture between many consumers (passive listener,
// Storm Guard, ARP sweeps, SYN-ACK fingerprinting).
package capture

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ErrTimeout is returned by ReadPacket when no packet arrived in time.
var ErrTimeout = errors.New("capture: read timeout")

// ErrUnsupported means raw capture isn't possible on this platform/host.
var ErrUnsupported = errors.New("capture: raw packet access not available")

// Handle is a raw Ethernet capture on one interface.
type Handle interface {
	// ReadPacket returns the next frame. The slice is owned by the caller.
	ReadPacket() ([]byte, time.Time, error)
	WritePacket([]byte) error
	Close() error
}

// Packet is a captured frame delivered to hub subscribers.
type Packet struct {
	Data []byte
	TS   time.Time
}

// Hub fans one Handle out to many subscribers.
type Hub struct {
	Iface net.Interface
	h     Handle

	mu     sync.RWMutex
	subs   map[uint64]*sub
	nextID uint64
	closed atomic.Bool
	done   chan struct{}
	refs   int

	Received atomic.Uint64
	Dropped  atomic.Uint64
	wmu      sync.Mutex
}

type sub struct {
	name string
	ch   chan Packet
}

// Subscribe returns a channel receiving copies of every frame. Frames are
// dropped (and counted) if the subscriber falls behind.
func (h *Hub) Subscribe(name string, buffer int) (<-chan Packet, func()) {
	if buffer <= 0 {
		buffer = 4096
	}
	h.mu.Lock()
	h.nextID++
	id := h.nextID
	s := &sub{name: name, ch: make(chan Packet, buffer)}
	h.subs[id] = s
	h.mu.Unlock()
	var once sync.Once
	return s.ch, func() {
		once.Do(func() {
			h.mu.Lock()
			if _, ok := h.subs[id]; ok {
				delete(h.subs, id)
				close(s.ch)
			}
			h.mu.Unlock()
		})
	}
}

// Write sends a raw Ethernet frame.
func (h *Hub) Write(frame []byte) error {
	if h.closed.Load() {
		return net.ErrClosed
	}
	h.wmu.Lock()
	defer h.wmu.Unlock()
	return h.h.WritePacket(frame)
}

func (h *Hub) loop() {
	defer close(h.done)
	for !h.closed.Load() {
		data, ts, err := h.h.ReadPacket()
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				continue
			}
			if h.closed.Load() {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		h.Received.Add(1)
		h.mu.RLock()
		for _, s := range h.subs {
			select {
			case s.ch <- Packet{Data: data, TS: ts}:
			default:
				h.Dropped.Add(1)
			}
		}
		h.mu.RUnlock()
	}
}

func (h *Hub) shutdown() {
	if h.closed.Swap(true) {
		return
	}
	h.h.Close()
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
	}
	h.mu.Lock()
	for id, s := range h.subs {
		close(s.ch)
		delete(h.subs, id)
	}
	h.mu.Unlock()
}

// ---- shared hubs ----

var (
	hubsMu sync.Mutex
	hubs   = map[string]*Hub{}
)

// Acquire opens (or reuses) a promiscuous capture on ifname. Call Release
// when finished.
func Acquire(ifname string) (*Hub, error) {
	hubsMu.Lock()
	defer hubsMu.Unlock()
	if h, ok := hubs[ifname]; ok {
		h.refs++
		return h, nil
	}
	ifc, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", ifname, err)
	}
	handle, err := open(*ifc, true)
	if err != nil {
		return nil, err
	}
	h := &Hub{Iface: *ifc, h: handle, subs: map[uint64]*sub{}, done: make(chan struct{}), refs: 1}
	hubs[ifname] = h
	go h.loop()
	return h, nil
}

// Release drops one reference to the hub, closing it at zero.
func Release(h *Hub) {
	if h == nil {
		return
	}
	hubsMu.Lock()
	h.refs--
	last := h.refs <= 0
	if last {
		delete(hubs, h.Iface.Name)
	}
	hubsMu.Unlock()
	if last {
		h.shutdown()
	}
}

// Probe reports whether raw capture works on ifname, with a human
// explanation when it doesn't.
func Probe(ifname string) (bool, string) {
	hubsMu.Lock()
	_, open := hubs[ifname]
	hubsMu.Unlock()
	if open {
		return true, ""
	}
	ifc, err := net.InterfaceByName(ifname)
	if err != nil {
		return false, err.Error()
	}
	h, err := openFn(*ifc, false)
	if err != nil {
		return false, explain(err)
	}
	h.Close()
	return true, ""
}

var openFn = open
