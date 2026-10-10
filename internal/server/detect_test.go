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

// TestMitreTechniqueCoverage ensures no behavioral rule ships without a mapping.
func TestMitreTechniqueCoverage(t *testing.T) {
	for _, rule := range []string{"reverse_shell", "shell_listener", "crypto_miner", "recon_tool", "exec_storm"} {
		if mitreTechnique[rule] == "" {
			t.Errorf("rule %q has no MITRE ATT&CK mapping", rule)
		}
	}
}
