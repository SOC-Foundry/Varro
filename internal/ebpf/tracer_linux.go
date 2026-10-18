//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// sensorDebug logs raw kernel-sensor events for live diagnosis when
// VARRO_SENSOR_DEBUG is set. Off by default.
var sensorDebug = os.Getenv("VARRO_SENSOR_DEBUG") != ""

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

// FileEvent is one openat()-for-write under a persistence root (/etc, /boot,
// /root), attributed to the writing process. The root is gated in the kernel;
// the agent refines to the paths it cares about.
type FileEvent struct {
	PID  uint32
	Comm string
	Path string
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

	filesLink   link.Link
	filesReader *ringbuf.Reader

	mu      sync.Mutex
	buf     []ExecEvent
	connBuf []ConnEvent
	fileBuf []FileEvent
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

	// File-write sensor, also best-effort within a working tracer.
	if flk, err := link.Tracepoint("syscalls", "sys_enter_openat", t.objs.TraceOpenat, nil); err == nil {
		if frd, err := ringbuf.NewReader(t.objs.Files); err == nil {
			t.filesLink = flk
			t.filesReader = frd
			go t.loopFiles()
			if sensorDebug {
				log.Printf("varro file-sensor: openat tracepoint attached")
			}
		} else {
			flk.Close()
			if sensorDebug {
				log.Printf("varro file-sensor: ringbuf reader failed: %v", err)
			}
		}
	} else if sensorDebug {
		log.Printf("varro file-sensor: openat tracepoint attach failed: %v", err)
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

func (t *Tracer) loopFiles() {
	for {
		rec, err := t.filesReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		var e struct {
			PID      uint32
			Comm     [16]byte
			Filename [256]byte
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
		path := string(bytes.TrimRight(e.Filename[:], "\x00"))
		if sensorDebug {
			log.Printf("varro file-sensor raw: comm=%q path=%q", comm, path)
		}
		t.mu.Lock()
		if !t.closed && len(t.fileBuf) < maxBuffered {
			t.fileBuf = append(t.fileBuf, FileEvent{PID: e.PID, Comm: comm, Path: path})
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

// DrainFiles returns and clears the file-write events buffered since the last call.
func (t *Tracer) DrainFiles() []FileEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.fileBuf
	t.fileBuf = nil
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
	if t.filesReader != nil {
		t.filesReader.Close()
	}
	if t.link != nil {
		t.link.Close()
	}
	if t.connLink != nil {
		t.connLink.Close()
	}
	if t.filesLink != nil {
		t.filesLink.Close()
	}
	t.objs.Close()
}
