//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ExecEvent is one observed process exec.
type ExecEvent struct {
	PID  uint32
	Comm string
}

// ConnEvent is one observed outbound TCP connect (including short-lived ones),
// attributed to the connecting process.
type ConnEvent struct {
	PID  uint32
	Comm string
	Dest string // destination IP
	Port uint16
}

// Tracer attaches the exec + connect tracepoints and streams their events. It
// is best-effort: if the kernel is too old, BPF is unavailable, or the agent
// lacks privilege, Start returns an error and the agent runs without it. The
// connect sensor is additionally best-effort within a working tracer.
type Tracer struct {
	objs   execObjects
	link   link.Link
	reader *ringbuf.Reader

	connLink   link.Link
	connReader *ringbuf.Reader

	mu      sync.Mutex
	buf     []ExecEvent
	connBuf []ConnEvent
	closed  bool
}

const maxBuffered = 1000 // cap between drains so a fork bomb can't grow unbounded

// Start loads and attaches the sensor and begins buffering events.
func Start() (*Tracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}
	t := &Tracer{}
	if err := loadExecObjects(&t.objs, nil); err != nil {
		return nil, err
	}
	lk, err := link.Tracepoint("sched", "sched_process_exec", t.objs.TraceExec, nil)
	if err != nil {
		t.objs.Close()
		return nil, err
	}
	t.link = lk
	rd, err := ringbuf.NewReader(t.objs.Events)
	if err != nil {
		lk.Close()
		t.objs.Close()
		return nil, err
	}
	t.reader = rd

	// Connect sensor is best-effort within a working tracer: if it can't
	// attach, exec capture still runs.
	if clk, err := link.Tracepoint("sock", "inet_sock_set_state", t.objs.TraceConnect, nil); err == nil {
		if crd, err := ringbuf.NewReader(t.objs.Conns); err == nil {
			t.connLink = clk
			t.connReader = crd
			go t.loopConns()
		} else {
			clk.Close()
		}
	}

	go t.loop()
	return t, nil
}

func (t *Tracer) loop() {
	for {
		rec, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		var e struct {
			PID  uint32
			Comm [16]byte
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
		t.mu.Lock()
		if !t.closed && len(t.buf) < maxBuffered {
			t.buf = append(t.buf, ExecEvent{PID: e.PID, Comm: comm})
		}
		t.mu.Unlock()
	}
}

func (t *Tracer) loopConns() {
	for {
		rec, err := t.connReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		var e struct {
			PID    uint32
			Dport  uint16
			Family uint16
			Daddr  [4]byte
			Daddr6 [16]byte
			Comm   [16]byte
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		var dest string
		if e.Family == 10 { // AF_INET6
			dest = net.IP(e.Daddr6[:]).String()
		} else {
			dest = net.IP(e.Daddr[:]).String()
		}
		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
		t.mu.Lock()
		if !t.closed && len(t.connBuf) < maxBuffered {
			t.connBuf = append(t.connBuf, ConnEvent{PID: e.PID, Comm: comm, Dest: dest, Port: e.Dport})
		}
		t.mu.Unlock()
	}
}

// Drain returns and clears the exec events buffered since the last call.
func (t *Tracer) Drain() []ExecEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.buf
	t.buf = nil
	return out
}

// DrainConns returns and clears the connect events buffered since the last call.
func (t *Tracer) DrainConns() []ConnEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.connBuf
	t.connBuf = nil
	return out
}

func (t *Tracer) Close() {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	if t.reader != nil {
		t.reader.Close()
	}
	if t.connReader != nil {
		t.connReader.Close()
	}
	if t.link != nil {
		t.link.Close()
	}
	if t.connLink != nil {
		t.connLink.Close()
	}
	t.objs.Close()
}
