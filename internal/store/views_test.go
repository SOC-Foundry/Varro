package store

import (
	"context"
	"testing"
)

func TestSavedViewsCRUD(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.SaveView(ctx, "a@x.com", "org1", "cpu-fleet", `{"metric":"cpu_percent"}`); err != nil {
		t.Fatal(err)
	}
	// Re-save same owner+name replaces (idempotent), doesn't duplicate.
	if err := s.SaveView(ctx, "a@x.com", "org1", "cpu-fleet", `{"metric":"mem_percent"}`); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveView(ctx, "a@x.com", "org1", "net", `{"metric":"rx_rate_bps"}`); err != nil {
		t.Fatal(err)
	}
	// A different owner's view must not leak.
	if err := s.SaveView(ctx, "b@x.com", "org1", "theirs", `{}`); err != nil {
		t.Fatal(err)
	}

	views, err := s.ListViews(ctx, "a@x.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 2 {
		t.Fatalf("owner a has %d views, want 2 (cpu-fleet replaced, not duped)", len(views))
	}
	var cpu *int64
	for i := range views {
		if views[i].Name == "cpu-fleet" {
			if views[i].Spec != `{"metric":"mem_percent"}` {
				t.Errorf("cpu-fleet spec = %s, want the replaced mem_percent", views[i].Spec)
			}
			cpu = &views[i].ID
		}
	}
	if cpu == nil {
		t.Fatal("cpu-fleet view missing")
	}

	// Delete is owner-scoped.
	if removed, err := s.DeleteView(ctx, "b@x.com", *cpu); err != nil || removed {
		t.Fatalf("cross-owner delete should fail: removed=%v err=%v", removed, err)
	}
	if removed, err := s.DeleteView(ctx, "a@x.com", *cpu); err != nil || !removed {
		t.Fatalf("owner delete should succeed: removed=%v err=%v", removed, err)
	}
	if views, _ := s.ListViews(ctx, "a@x.com"); len(views) != 1 {
		t.Fatalf("after delete owner a has %d views, want 1", len(views))
	}
}
