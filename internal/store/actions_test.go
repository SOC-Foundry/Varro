package store

import (
	"context"
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestActionApprovalFlow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Proposed action is NOT claimable by the agent.
	id, err := s.EnqueueAction(ctx, "ep1", model.ActionBlockIP, "1.2.3.4", "alice@x", model.ActionProposed)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := s.ClaimActions(ctx, "ep1"); len(c) != 0 {
		t.Fatalf("proposed action must not be claimable, got %d", len(c))
	}

	// Reject a second proposed action.
	id2, _ := s.EnqueueAction(ctx, "ep1", model.ActionKillProcess, "42", "alice@x", model.ActionProposed)
	if ok, _ := s.RejectAction(ctx, id2, "bob@x"); !ok {
		t.Fatal("reject should succeed on a proposed action")
	}
	if ok, _ := s.RejectAction(ctx, id2, "bob@x"); ok {
		t.Error("re-reject should be a no-op")
	}

	// Approve the first → becomes pending → claimable exactly once.
	if ok, _ := s.ApproveAction(ctx, id, "bob@x"); !ok {
		t.Fatal("approve should succeed on a proposed action")
	}
	if ok, _ := s.ApproveAction(ctx, id, "bob@x"); ok {
		t.Error("re-approve should be a no-op")
	}
	claimed, _ := s.ClaimActions(ctx, "ep1")
	if len(claimed) != 1 || claimed[0].ID != id {
		t.Fatalf("approved action should be claimable: %+v", claimed)
	}

	// Statuses + approver are recorded.
	acts, _ := s.Actions(ctx, "ep1", 10)
	byID := map[int64]model.Action{}
	for _, a := range acts {
		byID[a.ID] = a
	}
	if a := byID[id]; a.Status != model.ActionSent || a.ApprovedBy != "bob@x" {
		t.Errorf("approved+claimed action = %+v, want status=sent approved_by=bob@x", a)
	}
	if a := byID[id2]; a.Status != model.ActionRejected {
		t.Errorf("rejected action status = %q, want rejected", a.Status)
	}

	// Auto-response path: pending directly → immediately claimable.
	auto, _ := s.EnqueueAction(ctx, "ep2", model.ActionIsolate, "", "auto:pb", model.ActionPending)
	if c, _ := s.ClaimActions(ctx, "ep2"); len(c) != 1 || c[0].ID != auto {
		t.Errorf("auto-response (pending) action should be immediately claimable: %+v", c)
	}
}
