package store

import (
	"context"
	"testing"
)

func TestDashboardsCRUD(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	spec := `{"panels":[{"title":"cpu","metric":"cpu_percent","minutes":60,"endpoints":["a"]}]}`
	if err := s.SaveDashboard(ctx, "a@x.com", "org1", "ops", spec); err != nil {
		t.Fatal(err)
	}
	// Re-save same owner+name replaces, not duplicates.
	spec2 := `{"panels":[{"title":"mem","metric":"mem_percent","minutes":360,"endpoints":["b"]}]}`
	if err := s.SaveDashboard(ctx, "a@x.com", "org1", "ops", spec2); err != nil {
		t.Fatal(err)
	}
	// Another owner's dashboard must not leak.
	if err := s.SaveDashboard(ctx, "b@x.com", "org1", "theirs", spec); err != nil {
		t.Fatal(err)
	}

	dashes, err := s.ListDashboards(ctx, "a@x.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(dashes) != 1 {
		t.Fatalf("owner a has %d dashboards, want 1 (ops replaced)", len(dashes))
	}
	if dashes[0].Spec != spec2 {
		t.Errorf("ops spec = %s, want the replaced mem spec", dashes[0].Spec)
	}

	// Delete is owner-scoped.
	id := dashes[0].ID
	if removed, err := s.DeleteDashboard(ctx, "b@x.com", id); err != nil || removed {
		t.Fatalf("cross-owner delete should fail: removed=%v err=%v", removed, err)
	}
	if removed, err := s.DeleteDashboard(ctx, "a@x.com", id); err != nil || !removed {
		t.Fatalf("owner delete should succeed: removed=%v err=%v", removed, err)
	}
	if d, _ := s.ListDashboards(ctx, "a@x.com"); len(d) != 0 {
		t.Fatalf("after delete owner a has %d dashboards, want 0", len(d))
	}
}
