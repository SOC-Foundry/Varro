package server

import (
	"context"
	"testing"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// TestBuildReportAggregates checks that buildReport rolls up posture pass/fail,
// patch/service health, and vuln severity across the fleet's latest snapshots.
func TestBuildReportAggregates(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Two endpoints: one healthy, one with a posture failure + reboot + a
	// failed service + pending updates.
	snaps := []*model.Snapshot{
		{
			AgentID: "ep-1", Hostname: "clean", Timestamp: now,
			Host: model.HostInfo{OS: "linux"},
			Posture: []model.PostureCheck{
				{ID: "fw", Desc: "Firewall enabled", Status: model.PosturePass},
				{ID: "disk", Desc: "Disk encrypted", Status: model.PosturePass},
			},
			Health: model.HealthStatus{PendingUpdates: 0},
		},
		{
			AgentID: "ep-2", Hostname: "weak", Timestamp: now,
			Host: model.HostInfo{OS: "linux"},
			Posture: []model.PostureCheck{
				{ID: "fw", Desc: "Firewall enabled", Status: model.PostureFail},
				{ID: "disk", Desc: "Disk encrypted", Status: model.PosturePass},
			},
			Health: model.HealthStatus{PendingUpdates: 7, RebootRequired: true, FailedServices: []string{"nginx"}},
		},
	}
	if err := st.Insert(ctx, snaps, ""); err != nil {
		t.Fatalf("insert: %v", err)
	}

	rep, err := srv.buildReport(ctx, nil)
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}

	if rep.Endpoints != 2 {
		t.Fatalf("endpoints = %d, want 2", rep.Endpoints)
	}
	if rep.PosturePass != 3 || rep.PostureFail != 1 {
		t.Fatalf("posture pass/fail = %d/%d, want 3/1", rep.PosturePass, rep.PostureFail)
	}
	if rep.PostureScore != 75 { // 3 / (3+1) = 75%
		t.Fatalf("posture score = %d, want 75", rep.PostureScore)
	}
	if rep.PendingUpdates != 7 {
		t.Fatalf("pending updates = %d, want 7", rep.PendingUpdates)
	}
	if rep.RebootRequired != 1 {
		t.Fatalf("reboot required = %d, want 1", rep.RebootRequired)
	}
	if rep.FailedServices != 1 {
		t.Fatalf("failed services = %d, want 1", rep.FailedServices)
	}
	// Worst check (the firewall, with a failure) should sort first.
	if len(rep.PostureChecks) == 0 || rep.PostureChecks[0].ID != "fw" {
		t.Fatalf("expected firewall check first (worst), got %+v", rep.PostureChecks)
	}
	if rep.PostureChecks[0].Fail != 1 {
		t.Fatalf("firewall fail = %d, want 1", rep.PostureChecks[0].Fail)
	}
}
