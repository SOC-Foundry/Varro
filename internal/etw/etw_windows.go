//go:build windows

package etw

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/soc-foundry/varro/internal/model"
	"golang.org/x/sys/windows"
)

// Windows ETW exec sensor: a real-time consumer of the Microsoft-Windows-Kernel-
// Process provider's ProcessStart events, giving short-lived process capture the
// polling sensor misses — the Windows analog of the Linux eBPF exec sensor.
//
// Default-on since v0.85.0: the ETW session (StartTraceW → EnableTraceEx2 →
// OpenTraceW → ProcessTrace) is validated to open + run + close without crashing
// on a real Windows runner in CI (internal/etw TestETWExercise on windows-latest).
// Still defensive: any Start() failure (e.g. a non-admin host) returns an error so
// the agent falls back to the polling sensor, and the event callback is
// panic-contained. Event-field parsing (PID / image name) is best-effort and may
// want a TDH-based refinement. See docs/agent-platforms.md.
//
// Kernel-Process provider GUID {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}.
var kernelProcessGUID = windows.GUID{
	Data1: 0x22FB2CD6, Data2: 0x0E7B, Data3: 0x422B,
	Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16},
}

const (
	wnodeFlagTracedGUID    = 0x00020000
	eventTraceRealTimeMode = 0x00000100
	processTraceModeRT     = 0x00000100
	processTraceModeRecord = 0x10000000
	eventControlEnable     = 1
	keywordProcess         = 0x10 // WINEVENT_KEYWORD_PROCESS
	opcodeStart            = 1    // ProcessStart
	levelInformation       = 4
	sessionName            = "VarroExecSensor"
)

var (
	advapi32          = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW   = advapi32.NewProc("StartTraceW")
	procEnableTrace2  = advapi32.NewProc("EnableTraceEx2")
	procControlTraceW = advapi32.NewProc("ControlTraceW")
	procOpenTraceW    = advapi32.NewProc("OpenTraceW")
	procProcessTrace  = advapi32.NewProc("ProcessTrace")
	procCloseTrace    = advapi32.NewProc("CloseTrace")
)

type wnodeHeader struct {
	BufferSize        uint32
	ProviderId        uint32
	HistoricalContext uint64
	TimeStamp         int64
	Guid              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadId      windows.Handle
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

type eventDescriptor struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       int64
	ProviderId      windows.GUID
	EventDescriptor eventDescriptor
	ProcessorTime   uint64 // union KERNEL_TIME/USER_TIME or PROCESSOR_TIME
	ActivityId      windows.GUID
}

type etwBufferContext struct {
	ProcessorNumber uint8
	Alignment       uint8
	LoggerId        uint16
}

type eventRecord struct {
	EventHeader       eventHeader
	BufferContext     etwBufferContext
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      unsafe.Pointer
	UserData          unsafe.Pointer
	UserContext       unsafe.Pointer
}

// eventTraceLogfile mirrors EVENT_TRACE_LOGFILEW. The embedded CurrentEvent +
// LogfileHeader are large and we never read them, but their exact size must match
// C so EventRecordCallback lands at the right offset — represented as sized byte
// blobs. (This is the layout most at risk without a Windows host to verify.)
type eventTraceLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        [112]byte // EVENT_TRACE
	LogfileHeader       [272]byte // TRACE_LOGFILE_HEADER
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	Context             uintptr
}

// Tracer holds the drained process-start events.
type Tracer struct {
	mu       sync.Mutex
	events   []model.ExecSample
	traceH   uintptr
	sessionH uintptr
	closed   bool
}

var active *Tracer // the callback is a C function pointer; route to the live tracer

// Start opens a real-time ETW session for process-start events. Opt-in via
// VARRO_ETW; returns an error (→ caller falls back to the polling sensor) on any
// setup failure.
func Start() (*Tracer, error) {
	name, _ := windows.UTF16FromString(sessionName)
	// Buffer: properties struct + room for the session name at LoggerNameOffset.
	propSize := uint32(unsafe.Sizeof(eventTraceProperties{}))
	buf := make([]byte, propSize+uint32(len(name)*2))
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(len(buf))
	props.Wnode.Flags = wnodeFlagTracedGUID
	props.LogFileMode = eventTraceRealTimeMode
	props.LoggerNameOffset = propSize

	// Best-effort stop of a leftover session from a prior run.
	stopProps := make([]byte, propSize+uint32(len(name)*2))
	sp := (*eventTraceProperties)(unsafe.Pointer(&stopProps[0]))
	sp.Wnode.BufferSize = uint32(len(stopProps))
	sp.LoggerNameOffset = propSize
	copyU16(stopProps[propSize:], name)
	procControlTraceW.Call(0, uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(sp)), 1 /*STOP*/)

	var sessionH uintptr
	r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&sessionH)),
		uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(props)))
	if r != 0 {
		return nil, fmt.Errorf("StartTraceW failed: %d", r)
	}

	r, _, _ = procEnableTrace2.Call(sessionH, uintptr(unsafe.Pointer(&kernelProcessGUID)),
		eventControlEnable, levelInformation, keywordProcess, 0, 0, 0)
	if r != 0 {
		procControlTraceW.Call(sessionH, 0, uintptr(unsafe.Pointer(props)), 1)
		return nil, fmt.Errorf("EnableTraceEx2 failed: %d", r)
	}

	t := &Tracer{sessionH: sessionH}
	active = t

	var logfile eventTraceLogfile
	logfile.LoggerName = &name[0]
	logfile.ProcessTraceMode = processTraceModeRT | processTraceModeRecord
	logfile.EventRecordCallback = windows.NewCallback(eventRecordCallback)
	traceH, _, _ := procOpenTraceW.Call(uintptr(unsafe.Pointer(&logfile)))
	if traceH == ^uintptr(0) { // INVALID_PROCESSTRACE_HANDLE
		procControlTraceW.Call(sessionH, 0, uintptr(unsafe.Pointer(props)), 1)
		return nil, fmt.Errorf("OpenTraceW failed")
	}
	t.traceH = traceH

	// ProcessTrace blocks, driving the callback; run it detached. A panic in the
	// Go portion is recovered so a parsing bug degrades (no events) rather than
	// taking down the agent. (A struct-layout fault in the syscall itself is NOT
	// recoverable — hence opt-in + the Windows-validation requirement.)
	go func() {
		defer func() { _ = recover() }()
		handles := []uintptr{traceH}
		procProcessTrace.Call(uintptr(unsafe.Pointer(&handles[0])), 1, 0, 0)
	}()

	return t, nil
}

// eventRecordCallback is invoked by ETW per event; keep it panic-safe.
func eventRecordCallback(rec *eventRecord) uintptr {
	defer func() { _ = recover() }()
	t := active
	if t == nil || rec == nil {
		return 0
	}
	if rec.EventHeader.EventDescriptor.Opcode != opcodeStart {
		return 0
	}
	n := int(rec.UserDataLength)
	if n < 4 || rec.UserData == nil {
		return 0
	}
	data := unsafe.Slice((*byte)(rec.UserData), n)
	// ProcessStart UserData begins with the new ProcessID (uint32), followed by
	// other fields and a UTF-16 ImageName. Read the PID, then best-effort scan
	// for the image name — all bounds-checked.
	pid := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	comm := scanUTF16Name(data)
	t.mu.Lock()
	if !t.closed && len(t.events) < 4096 {
		t.events = append(t.events, model.ExecSample{PID: pid, Comm: comm})
	}
	t.mu.Unlock()
	return 0
}

// scanUTF16Name finds the first plausible null-terminated UTF-16 run in the event
// data and returns its trailing path component. Defensive: never reads out of
// bounds; returns "" if nothing sensible is found.
func scanUTF16Name(data []byte) string {
	best := ""
	for off := 4; off+2 <= len(data); off += 2 {
		var u16 []uint16
		for i := off; i+2 <= len(data); i += 2 {
			c := uint16(data[i]) | uint16(data[i+1])<<8
			if c == 0 {
				break
			}
			if c < 0x20 || c > 0x7e { // keep it to printable ASCII-range to avoid garbage
				u16 = nil
				break
			}
			u16 = append(u16, c)
		}
		if len(u16) >= 4 {
			best = windows.UTF16ToString(append(u16, 0))
			break
		}
	}
	// trailing path component
	for i := len(best) - 1; i >= 0; i-- {
		if best[i] == '\\' || best[i] == '/' {
			return best[i+1:]
		}
	}
	return best
}

// Drain returns and clears buffered process-start events.
func (t *Tracer) Drain() []model.ExecSample {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.events
	t.events = nil
	return out
}

func (t *Tracer) Close() {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	if t.traceH != 0 {
		procCloseTrace.Call(t.traceH)
	}
}

func copyU16(dst []byte, src []uint16) {
	for i, c := range src {
		if i*2+1 >= len(dst) {
			break
		}
		dst[i*2] = byte(c)
		dst[i*2+1] = byte(c >> 8)
	}
}

var _ = time.Now // (reserved for future event timestamping)
