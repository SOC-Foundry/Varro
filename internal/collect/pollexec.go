package collect

import (
	"sync"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/soc-foundry/varro/internal/model"
)

// PollExecTracer is a portable process-start sensor: it diffs the process table
// between samples and reports newly-appeared PIDs as exec events. It satisfies
// the same Drain() interface the eBPF tracer does, so on platforms without the
// kernel sensor (Windows, macOS, old/unprivileged Linux) the agent still feeds
// process-start signal to the detection engine.
//
// Unlike the eBPF sensor it cannot catch processes that start AND exit within one
// sample interval; it catches everything still alive at the next poll.
type PollExecTracer struct {
	mu       sync.Mutex
	seen     map[int32]struct{}
	listPids func() ([]int32, error) // injectable for tests
	nameOf   func(int32) string      // injectable for tests
	capAt    int                     // max events per drain (burst guard)
}

// NewPollExecTracer builds a polling exec sensor backed by gopsutil.
func NewPollExecTracer() *PollExecTracer {
	return &PollExecTracer{
		listPids: process.Pids,
		nameOf: func(pid int32) string {
			if p, err := process.NewProcess(pid); err == nil {
				if n, err := p.Name(); err == nil {
					return n
				}
			}
			return ""
		},
		capAt: 256,
	}
}

// Drain returns processes that appeared since the previous call. The first call
// only establishes the baseline (returns nothing) so existing processes aren't
// reported as new.
func (p *PollExecTracer) Drain() []model.ExecSample {
	pids, err := p.listPids()
	if err != nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	first := p.seen == nil
	cur := make(map[int32]struct{}, len(pids))
	var out []model.ExecSample
	for _, pid := range pids {
		cur[pid] = struct{}{}
		if first {
			continue
		}
		if _, ok := p.seen[pid]; !ok {
			if len(out) < p.capAt {
				out = append(out, model.ExecSample{PID: uint32(pid), Comm: p.nameOf(pid)})
			}
		}
	}
	p.seen = cur
	return out
}
