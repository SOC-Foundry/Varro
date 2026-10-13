package store

import (
	"context"
	"testing"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

func TestSyntheticChecksCRUDAndScope(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	a, err := s.CreateSyntheticCheck(ctx, model.SyntheticCheck{
		OrgID: "org1", Name: "api", Type: "http", Target: "https://a.example/health",
		IntervalS: 60, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == "" {
		t.Fatal("created check has no ID")
	}
	if _, err := s.CreateSyntheticCheck(ctx, model.SyntheticCheck{
		OrgID: "org2", Name: "db", Type: "tcp", Target: "db.example:5432", IntervalS: 30, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	// Scope isolation: org1 only sees its own check.
	got, err := s.SyntheticChecks(ctx, []string{"org1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "api" {
		t.Fatalf("org1 scope = %+v, want just api", got)
	}

	// EnabledSyntheticChecks spans orgs (prober work list).
	all, err := s.EnabledSyntheticChecks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("enabled checks = %d, want 2", len(all))
	}

	// Cross-scope delete must not remove org1's check.
	if removed, err := s.DeleteSyntheticCheck(ctx, []string{"org2"}, a.ID); err != nil || removed {
		t.Fatalf("cross-scope delete should fail: removed=%v err=%v", removed, err)
	}
	if removed, err := s.DeleteSyntheticCheck(ctx, []string{"org1"}, a.ID); err != nil || !removed {
		t.Fatalf("in-scope delete should succeed: removed=%v err=%v", removed, err)
	}
	if got, _ := s.SyntheticChecks(ctx, []string{"org1"}); len(got) != 0 {
		t.Fatalf("after delete org1 has %d checks, want 0", len(got))
	}
}

func TestProbeResultsAndStatus(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	c, err := s.CreateSyntheticCheck(ctx, model.SyntheticCheck{
		OrgID: "org1", Name: "api", Type: "http", Target: "https://a.example", IntervalS: 60, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	// 4 results: 3 ok, 1 down → 75% uptime; newest is the "down" one.
	rows := []model.ProbeResult{
		{CheckID: c.ID, TS: now - 300, OK: true, LatencyMs: 40, Code: 200},
		{CheckID: c.ID, TS: now - 200, OK: true, LatencyMs: 55, Code: 200},
		{CheckID: c.ID, TS: now - 100, OK: true, LatencyMs: 48, Code: 200},
		{CheckID: c.ID, TS: now - 10, OK: false, LatencyMs: 0, Code: 503, Error: "unexpected status 503"},
	}
	for _, r := range rows {
		if err := s.InsertProbeResult(ctx, r, "org1"); err != nil {
			t.Fatal(err)
		}
	}

	st, err := s.SyntheticStatuses(ctx, []string{"org1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 1 {
		t.Fatalf("statuses = %d, want 1", len(st))
	}
	got := st[0]
	if got.Up {
		t.Error("latest result was down; status should be down")
	}
	if got.LastCode != 503 {
		t.Errorf("last code = %d, want 503", got.LastCode)
	}
	if got.Samples24h != 4 {
		t.Errorf("samples_24h = %d, want 4", got.Samples24h)
	}
	if got.UptimePct < 74.9 || got.UptimePct > 75.1 {
		t.Errorf("uptime = %.2f, want 75", got.UptimePct)
	}

	// Results are scope-guarded.
	res, err := s.ProbeResults(ctx, []string{"org1"}, c.ID, now-3600, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 4 {
		t.Fatalf("results = %d, want 4", len(res))
	}
	if other, _ := s.ProbeResults(ctx, []string{"org2"}, c.ID, now-3600, 100); len(other) != 0 {
		t.Fatalf("org2 should not see org1 results, got %d", len(other))
	}
}
