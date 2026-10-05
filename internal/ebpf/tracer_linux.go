//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
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

// Tracer attaches the exec tracepoint and streams exec events. It is
// best-effort: if the kernel is too old, BPF is unavailable, or the agent
// lacks privilege, Start returns an error and the agent runs without it.
type Tracer struct {
	objs   execObjects
	link   link.Link
	reader *ringbuf.Reader

	mu     sync.Mutex
	buf    []ExecEvent
	closed bool
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

// Drain returns and clears the events buffered since the last call.
func (t *Tracer) Drain() []ExecEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.buf
	t.buf = nil
	return out
}

func (t *Tracer) Close() {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	if t.reader != nil {
		t.reader.Close()
	}
	if t.link != nil {
		t.link.Close()
	}
	t.objs.Close()
}
