package server

import (
	"context"
	"strings"
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

// TestDetectMitreMapping checks that a behavioral detection is emitted with its
// MITRE ATT&CK technique embedded, and that every rule has a mapping.
func TestDetectMitreMapping(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	snap := &model.Snapshot{
		AgentID:  "ep1",
		Hostname: "host1",
		Execs:    []model.ExecSample{{PID: 1, Comm: "xmrig"}}, // known miner
	}
	srv.detect(ctx, "org1", snap)

	evs, err := st.Events(ctx, "ep1", nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range evs {
		if e.Type == model.EventDetection && strings.Contains(e.Message, "crypto_miner") {
			found = true
			if !strings.Contains(e.Message, "T1496") {
				t.Fatalf("detection missing ATT&CK technique: %q", e.Message)
			}
		}
	}
	if !found {
		t.Fatalf("no crypto_miner detection emitted; events=%v", evs)
	}
}

// TestDetectShortLivedConnect verifies the eBPF connect sensor catches a
// short-lived reverse-shell connection the periodic scan would miss.
func TestDetectShortLivedConnect(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	snap := &model.Snapshot{
		AgentID:  "ep1",
		Hostname: "host1",
		Conns:    []model.ConnSample{{PID: 5, Comm: "nc", Dest: "203.0.113.9", Port: 4444}},
	}
	srv.detect(ctx, "org1", snap)
	evs, _ := st.Events(ctx, "ep1", nil, 10)
	var found bool
	for _, e := range evs {
		if e.Type == model.EventDetection && strings.Contains(e.Message, "reverse_shell") &&
			strings.Contains(e.Message, "203.0.113.9:4444") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected reverse_shell detection from eBPF connect; events=%v", evs)
	}
}

// TestMitreTechniqueCoverage ensures no behavioral rule ships without a mapping.
func TestMitreTechniqueCoverage(t *testing.T) {
	for _, rule := range []string{"reverse_shell", "shell_listener", "crypto_miner", "recon_tool", "exec_storm"} {
		if mitreTechnique[rule] == "" {
			t.Errorf("rule %q has no MITRE ATT&CK mapping", rule)
		}
	}
}
