package store

import (
	"context"
	"testing"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

func TestSampleRollups(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now()

	mk := func(ts time.Time, cpu float64) *model.Snapshot {
		return &model.Snapshot{
			AgentID: "ep1", Hostname: "h1", Timestamp: ts,
			CPU:    model.CPUMetrics{TotalPercent: cpu},
			Memory: model.MemoryMetrics{UsedPercent: 50},
		}
	}
	// Two samples in one old hour (avg cpu 20), one in the next hour (cpu 80).
	hourA := now.Add(-50 * time.Hour).Truncate(time.Hour).Add(5 * time.Minute)
	hourB := hourA.Add(time.Hour)
	if err := s.Insert(ctx, []*model.Snapshot{
		mk(hourA, 10), mk(hourA.Add(time.Minute), 30), mk(hourB, 80),
	}, "org1"); err != nil {
		t.Fatal(err)
	}
	if err := s.RollupSamples(ctx, now.Add(-72*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// A >36h window is served from rollups (two distinct hourly buckets).
	pts, err := s.History(ctx, "ep1", now.Add(-72*time.Hour), now, 60)
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != 2 {
		t.Fatalf("rollup points = %d, want 2 hourly buckets", len(pts))
	}
	if pts[0].CPUPercent < 19.9 || pts[0].CPUPercent > 20.1 {
		t.Errorf("hour A avg cpu = %.2f, want ~20", pts[0].CPUPercent)
	}
	if pts[1].CPUPercent < 79.9 || pts[1].CPUPercent > 80.1 {
		t.Errorf("hour B cpu = %.2f, want ~80", pts[1].CPUPercent)
	}

	// Idempotent: re-running the rollup doesn't duplicate buckets.
	if err := s.RollupSamples(ctx, now.Add(-72*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if pts2, _ := s.History(ctx, "ep1", now.Add(-72*time.Hour), now, 60); len(pts2) != 2 {
		t.Fatalf("after re-rollup points = %d, want 2 (idempotent)", len(pts2))
	}
}
