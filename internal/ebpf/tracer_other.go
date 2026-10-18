//go:build !linux

package ebpf

import "errors"

// ExecEvent mirrors the Linux type so callers compile everywhere.
type ExecEvent struct {
	PID  uint32
	Comm string
}

// ConnEvent mirrors the Linux type so callers compile everywhere.
type ConnEvent struct {
	PID  uint32
	Comm string
	Dest string
	Port uint16
}

// FileEvent mirrors the Linux type so callers compile everywhere.
type FileEvent struct {
	PID  uint32
	Comm string
	Path string
}

// Tracer is a no-op outside Linux.
type Tracer struct{}

// Start always fails off Linux; the agent runs without the eBPF sensor.
func Start() (*Tracer, error) { return nil, errors.New("eBPF exec sensor is Linux-only") }

func (t *Tracer) Drain() []ExecEvent      { return nil }
func (t *Tracer) DrainConns() []ConnEvent { return nil }
func (t *Tracer) DrainFiles() []FileEvent { return nil }
func (t *Tracer) Close()                  {}
