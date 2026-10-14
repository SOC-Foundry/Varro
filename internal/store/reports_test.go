package store

import (
	"context"
	"testing"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

func TestReportSchedules(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Default (no row) is disabled, weekly.
	if sc, _ := s.ReportSchedule(ctx, "org1"); sc.Enabled || sc.Cadence != "weekly" {
		t.Fatalf("default schedule = %+v, want disabled weekly", sc)
	}
	// Enable with recipients.
	if err := s.SetReportSchedule(ctx, model.ReportSchedule{
		OrgID: "org1", Enabled: true, Cadence: "weekly", Recipients: []string{"a@x.com", "b@x.com"},
	}); err != nil {
		t.Fatal(err)
	}
	sc, _ := s.ReportSchedule(ctx, "org1")
	if !sc.Enabled || len(sc.Recipients) != 2 {
		t.Fatalf("round-trip = %+v", sc)
	}

	// Freshly enabled (last_sent=0) → due now.
	due, err := s.DueReportSchedules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].OrgID != "org1" {
		t.Fatalf("due = %+v, want org1", due)
	}
	// After sending, not due again until the interval elapses.
	if err := s.MarkReportSent(ctx, "org1", time.Now()); err != nil {
		t.Fatal(err)
	}
	if due, _ := s.DueReportSchedules(ctx); len(due) != 0 {
		t.Fatalf("after send, due = %d, want 0", len(due))
	}
	// Disabled schedules are never due even if long overdue.
	s.SetReportSchedule(ctx, model.ReportSchedule{OrgID: "org2", Enabled: false, Cadence: "daily", Recipients: []string{"c@x.com"}})
	if due, _ := s.DueReportSchedules(ctx); len(due) != 0 {
		t.Fatalf("disabled schedule should not be due, got %d", len(due))
	}
}

func TestIncidentCounts(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	s.AttachSignal(ctx, "org1", "h1", "h1", "alert", "MEDIUM", "a", "m")
	s.AttachSignal(ctx, "org1", "h2", "h2", "detection", "CRITICAL", "b", "m")
	open, crit, err := s.IncidentCounts(ctx, "org1")
	if err != nil {
		t.Fatal(err)
	}
	if open != 2 || crit != 1 {
		t.Fatalf("counts = open %d crit %d, want 2 / 1", open, crit)
	}
	if o, _, _ := s.IncidentCounts(ctx, "org2"); o != 0 {
		t.Error("org2 should have 0 incidents")
	}
}
