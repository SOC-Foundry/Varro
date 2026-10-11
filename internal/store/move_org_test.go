package store

import (
	"context"
	"testing"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// TestMoveAgentOrg verifies an endpoint is reassigned to a new org and, crucially,
// that the agent's token->org binding moves too so the next ingest doesn't revert it.
func TestMoveAgentOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	infra, err := s.CreateOrg(ctx, "Infrastructure")
	if err != nil {
		t.Fatal(err)
	}

	// Endpoint "ep1" enrolls in the default org with its own agent token.
	if err := s.Insert(ctx, []*model.Snapshot{testSnapshot("ep1", now, 10)}, model.DefaultOrg); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAgentToken(ctx, "ep1", "hash-ep1", model.DefaultOrg); err != nil {
		t.Fatal(err)
	}

	moved, err := s.MoveAgentOrg(ctx, "ep1", infra.ID)
	if err != nil {
		t.Fatalf("MoveAgentOrg: %v", err)
	}
	if !moved {
		t.Fatal("expected moved=true for existing endpoint")
	}

	// Endpoint row now in the new org.
	if org, err := s.EndpointOrg(ctx, "ep1"); err != nil || org != infra.ID {
		t.Fatalf("endpoint org = %q (err %v), want %q", org, err, infra.ID)
	}
	// The token binding moved, so a fresh ingest's org is resolved as infra.
	if _, org, err := s.AgentToken(ctx, "ep1"); err != nil || org != infra.ID {
		t.Fatalf("agent token org = %q (err %v), want %q", org, err, infra.ID)
	}

	// A subsequent ingest under the resolved org keeps the endpoint there.
	if _, org, _ := s.AgentToken(ctx, "ep1"); org == infra.ID {
		if err := s.Insert(ctx, []*model.Snapshot{testSnapshot("ep1", now.Add(time.Second), 20)}, org); err != nil {
			t.Fatal(err)
		}
	}
	if org, _ := s.EndpointOrg(ctx, "ep1"); org != infra.ID {
		t.Fatalf("after re-ingest endpoint org = %q, want %q (move reverted!)", org, infra.ID)
	}

	// Unknown endpoint -> moved=false, no error.
	if moved, err := s.MoveAgentOrg(ctx, "nope", infra.ID); err != nil || moved {
		t.Fatalf("unknown endpoint: moved=%v err=%v, want false,nil", moved, err)
	}
}
