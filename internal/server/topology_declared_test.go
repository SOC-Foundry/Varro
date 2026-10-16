package server

import (
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestAddDeclaredOverlay(t *testing.T) {
	eps := []model.EndpointSummary{
		{ID: "pg", Hostname: "varro-pg"},
		{ID: "pg2", Hostname: "varro-pg-2"},
		{ID: "mon", Hostname: "varro-pg-mon"},
	}
	inScope := map[string]bool{"pg": true, "pg2": true, "mon": true}
	ips := newIPIndex()
	ips.set("10.0.0.10", "pg")
	ips.set("10.0.0.19", "mon")

	snaps := map[string]*model.Snapshot{
		"pg": {DeclaredDeps: []model.DeclaredDep{
			{Kind: model.DepKindHAMonitor, From: "pg_autoctl", TargetHost: "10.0.0.19", TargetPort: 5432, Hard: true},
			{Kind: model.DepKindSystemd, From: "pgautofailover.service", Target: "network.service", Hard: false},
		}},
		"pg2": {DeclaredDeps: []model.DeclaredDep{
			{Kind: model.DepKindReplication, From: "postgres", TargetHost: "10.0.0.10", TargetPort: 5432, Hard: true}, // → pg
			{Kind: model.DepKindHAMonitor, From: "pg_autoctl", TargetHost: "10.0.0.19", TargetPort: 5432, Hard: true}, // → mon
			{Kind: model.DepKindReplication, From: "postgres", TargetHost: "8.8.8.8", Hard: true},                     // external → dropped
		}},
		"mon": {},
	}
	nodes := []model.TopoNode{{ID: "pg"}, {ID: "pg2"}, {ID: "mon"}}
	var edges []model.TopoEdge

	addDeclaredOverlay(nodes, &edges, snaps, inScope, ips, eps)

	// Cross-host declared edges: pg→mon, pg2→pg, pg2→mon (external 8.8.8.8 dropped).
	type e struct{ s, d, k string }
	got := map[e]bool{}
	for _, x := range edges {
		if !x.Declared {
			t.Errorf("edge %+v not marked declared", x)
		}
		got[e{x.Src, x.Dst, x.DepKind}] = true
	}
	want := []e{{"pg", "mon", "ha-monitor"}, {"pg2", "pg", "replication"}, {"pg2", "mon", "ha-monitor"}}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing declared edge %+v; got %+v", w, edges)
		}
	}
	if len(edges) != 3 {
		t.Errorf("got %d declared edges, want 3 (external target dropped): %+v", len(edges), edges)
	}

	// systemd dep attached to the pg node inspector, not as an edge.
	var pgNode *model.TopoNode
	for i := range nodes {
		if nodes[i].ID == "pg" {
			pgNode = &nodes[i]
		}
	}
	if pgNode == nil || len(pgNode.DeclaredDeps) != 1 || pgNode.DeclaredDeps[0].Kind != model.DepKindSystemd {
		t.Errorf("pg node should carry 1 systemd declared dep, got %+v", pgNode)
	}
}
