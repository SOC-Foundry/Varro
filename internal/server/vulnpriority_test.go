package server

import (
	"context"
	"testing"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

func TestBuildVulnPriorityRanking(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	now := time.Now()

	// Two online endpoints; ep-crit has heavier findings than ep-high.
	for _, id := range []string{"ep-crit", "ep-high", "ep-clean"} {
		snap := &model.Snapshot{AgentID: id, Hostname: id, Timestamp: now, Host: model.HostInfo{OS: "linux"}}
		if err := st.Insert(ctx, []*model.Snapshot{snap}, model.DefaultOrg); err != nil {
			t.Fatal(err)
		}
	}
	mustVulns := func(ep string, vs []model.Vulnerability, sev map[string]string) {
		if _, err := st.ReplaceEndpointVulns(ctx, ep, vs, now.Unix()); err != nil {
			t.Fatal(err)
		}
		for id, s := range sev {
			if err := st.SetVulnDetail(ctx, id, s, ""); err != nil {
				t.Fatal(err)
			}
		}
	}
	mustVulns("ep-crit",
		[]model.Vulnerability{{ID: "C1", Package: "a", Version: "1"}, {ID: "C2", Package: "b", Version: "1"}},
		map[string]string{"C1": "critical", "C2": "critical"})
	mustVulns("ep-high",
		[]model.Vulnerability{{ID: "H1", Package: "c", Version: "1"}},
		map[string]string{"H1": "high"})
	// ep-clean has no vulns.

	out, err := srv.buildVulnPriority(ctx, nil)
	if err != nil {
		t.Fatalf("buildVulnPriority: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d prioritized hosts, want 2 (clean host excluded)", len(out))
	}
	if out[0].EndpointID != "ep-crit" {
		t.Fatalf("expected ep-crit ranked first, got %q (scores: %d vs %d)", out[0].EndpointID, out[0].Score, out[1].Score)
	}
	if out[0].Critical != 2 {
		t.Errorf("ep-crit critical = %d, want 2", out[0].Critical)
	}
	if out[0].Score <= out[1].Score {
		t.Errorf("ranking not by score: %d !> %d", out[0].Score, out[1].Score)
	}
	// Online, not internet-facing (no external edges): weight 2*10=20 × (1+0.5)=30.
	if out[0].Score != 30 {
		t.Errorf("ep-crit score = %d, want 30 (20 weight × 1.5 online)", out[0].Score)
	}
}
