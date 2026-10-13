package store

import (
	"context"
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestSearchEvents(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for _, m := range []string{"[HIGH] reverse_shell: bash to 1.2.3.4", "pkg installed curl", "[HIGH] reverse_shell: nc out"} {
		if err := s.InsertServerEvent(ctx, "org1", "host-a", model.EventDetection, m); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.InsertServerEvent(ctx, "org2", "host-b", model.EventDetection, "reverse_shell other org"); err != nil {
		t.Fatal(err)
	}
	// Text search, org-scoped.
	got, err := s.SearchEvents(ctx, []string{"org1"}, "reverse_shell", "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("org1 reverse_shell matches = %d, want 2", len(got))
	}
	if other, _ := s.SearchEvents(ctx, []string{"org2"}, "reverse_shell", "", 0, 100); len(other) != 1 {
		t.Fatalf("org2 should see only its own event, got %d", len(other))
	}
}

func TestHuntsCRUD(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if err := s.SaveHunt(ctx, "a@x.com", "org1", model.Hunt{Name: "shells", Query: "reverse_shell", Source: "events", Alerting: true, Threshold: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveHunt(ctx, "a@x.com", "org1", model.Hunt{Name: "noisy", Query: "x", Source: "all", Alerting: false, Threshold: 1}); err != nil {
		t.Fatal(err)
	}
	hunts, err := s.ListHunts(ctx, "a@x.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(hunts) != 2 {
		t.Fatalf("hunts = %d, want 2", len(hunts))
	}
	// Only the alerting one is in the evaluation set, with its org.
	al, err := s.AlertingHunts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(al) != 1 || al[0].Name != "shells" || al[0].OrgID != "org1" {
		t.Fatalf("alerting hunts = %+v, want just shells@org1", al)
	}
	// Owner-scoped delete.
	id := hunts[0].ID
	if ok, _ := s.DeleteHunt(ctx, "b@x.com", id); ok {
		t.Error("cross-owner delete should fail")
	}
	if ok, err := s.DeleteHunt(ctx, "a@x.com", id); err != nil || !ok {
		t.Errorf("owner delete: %v %v", ok, err)
	}
}
