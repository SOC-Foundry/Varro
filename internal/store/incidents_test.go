package store

import (
	"context"
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestIncidentCorrelation(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Two signals for the same endpoint within the window → one incident, 2 items,
	// severity raised to the max (and the second escalates it to CRITICAL).
	r1, err := s.AttachSignal(ctx, "org1", "host-a", "hostA", "alert", "MEDIUM", "Alert: high-cpu", "cpu high")
	if err != nil {
		t.Fatal(err)
	}
	if !r1.Created {
		t.Error("first signal should open a new incident")
	}
	r2, err := s.AttachSignal(ctx, "org1", "host-a", "hostA", "detection", "CRITICAL", "Detection: reverse_shell", "nc out")
	if err != nil {
		t.Fatal(err)
	}
	if r1.ID != r2.ID {
		t.Fatalf("same-endpoint signals should share an incident: %d vs %d", r1.ID, r2.ID)
	}
	if r2.Created || !r2.Escalated {
		t.Errorf("second signal should escalate (not create): created=%v escalated=%v", r2.Created, r2.Escalated)
	}
	id1 := r1.ID
	// A different endpoint → separate incident.
	r3, _ := s.AttachSignal(ctx, "org1", "host-b", "hostB", "detection", "HIGH", "Detection: miner", "xmrig")
	if r3.ID == id1 {
		t.Fatal("different endpoint should get a separate incident")
	}

	inc, err := s.IncidentDetail(ctx, id1)
	if err != nil || inc == nil {
		t.Fatalf("detail: %v", err)
	}
	if len(inc.Items) != 2 {
		t.Fatalf("incident items = %d, want 2", len(inc.Items))
	}
	if inc.Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL (raised)", inc.Severity)
	}

	// Scope + status filter.
	open, _ := s.Incidents(ctx, []string{"org1"}, "open", 100)
	if len(open) != 2 {
		t.Fatalf("open incidents = %d, want 2", len(open))
	}
	if other, _ := s.Incidents(ctx, []string{"org2"}, "", 100); len(other) != 0 {
		t.Error("org2 should see no incidents")
	}

	// Resolve, then a new signal starts a FRESH incident (not reopening).
	if err := s.SetIncidentStatus(ctx, id1, model.IncidentResolved, "analyst@x"); err != nil {
		t.Fatal(err)
	}
	r4, _ := s.AttachSignal(ctx, "org1", "host-a", "hostA", "alert", "LOW", "Alert: again", "x")
	if r4.ID == id1 || !r4.Created {
		t.Fatal("signal after resolve should open a new incident")
	}
	if d, _ := s.IncidentDetail(ctx, id1); d.Status != model.IncidentResolved || d.ResolvedAt == nil {
		t.Errorf("incident should be resolved with a resolved_at")
	}
}
