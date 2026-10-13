package collect

import "testing"

func TestPollExecTracer(t *testing.T) {
	pids := []int32{1, 2, 3}
	tr := &PollExecTracer{
		listPids: func() ([]int32, error) { return pids, nil },
		nameOf:   func(pid int32) string { return "proc" },
		capAt:    256,
	}
	// First drain establishes the baseline — no "new" processes.
	if got := tr.Drain(); len(got) != 0 {
		t.Fatalf("first drain = %d events, want 0 (baseline)", len(got))
	}
	// A new PID appears → one exec event.
	pids = []int32{1, 2, 3, 4}
	got := tr.Drain()
	if len(got) != 1 || got[0].PID != 4 {
		t.Fatalf("after new pid 4, drain = %+v, want one event for pid 4", got)
	}
	// Nothing new → no events (and a dead PID is forgotten, not reported).
	pids = []int32{1, 2, 4}
	if got := tr.Drain(); len(got) != 0 {
		t.Fatalf("steady state drain = %d events, want 0", len(got))
	}
	// Two new PIDs at once.
	pids = []int32{1, 2, 4, 7, 8}
	if got := tr.Drain(); len(got) != 2 {
		t.Fatalf("two new pids → %d events, want 2", len(got))
	}
}

func TestPollExecTracerCap(t *testing.T) {
	first := true
	tr := &PollExecTracer{
		listPids: func() ([]int32, error) {
			if first {
				first = false
				return nil, nil // empty baseline
			}
			ps := make([]int32, 500)
			for i := range ps {
				ps[i] = int32(i + 1)
			}
			return ps, nil
		},
		nameOf: func(int32) string { return "x" },
		capAt:  256,
	}
	tr.Drain() // baseline (empty)
	if got := tr.Drain(); len(got) != 256 {
		t.Fatalf("burst drain = %d, want capped at 256", len(got))
	}
}
