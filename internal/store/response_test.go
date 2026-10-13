package store

import (
	"context"
	"testing"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

func TestPlaybooksCRUDAndContainment(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	p, err := s.CreatePlaybook(ctx, model.Playbook{OrgID: "org1", Name: "isolate-crit", Enabled: true, OnSeverity: "HIGH", Action: "isolate"})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Playbooks(ctx, "org1"); len(got) != 1 || got[0].Name != "isolate-crit" {
		t.Fatalf("playbooks = %+v", got)
	}
	if other, _ := s.Playbooks(ctx, "org2"); len(other) != 0 {
		t.Error("org2 should have no playbooks")
	}
	// Containment tracking.
	if c, _ := s.LatestContainment(ctx, "host-a"); c != "" {
		t.Errorf("fresh host containment = %q, want empty", c)
	}
	s.EnqueueAction(ctx, "host-a", model.ActionIsolate, "", "auto:isolate-crit")
	if c, _ := s.LatestContainment(ctx, "host-a"); c != model.ActionIsolate {
		t.Errorf("after isolate, containment = %q, want isolate", c)
	}
	s.EnqueueAction(ctx, "host-a", model.ActionUnisolate, "", "op")
	if c, _ := s.LatestContainment(ctx, "host-a"); c != model.ActionUnisolate {
		t.Errorf("after unisolate, containment = %q, want unisolate", c)
	}
	if ok, _ := s.DeletePlaybook(ctx, "org2", p.ID); ok {
		t.Error("cross-org delete should fail")
	}
	if ok, _ := s.DeletePlaybook(ctx, "org1", p.ID); !ok {
		t.Error("delete should succeed")
	}
}

func TestSilencesActive(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if _, err := s.CreateSilence(ctx, model.Silence{OrgID: "org1", Name: "future", MatchRule: "cpu", Until: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSilence(ctx, model.Silence{OrgID: "org1", Name: "past", Until: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	all, _ := s.Silences(ctx, "org1")
	if len(all) != 2 {
		t.Fatalf("all silences = %d, want 2", len(all))
	}
	active, err := s.ActiveSilences(ctx, "org1")
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].Name != "future" {
		t.Fatalf("active = %+v, want just the future one", active)
	}
}
