package server

import (
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestComputeImpact(t *testing.T) {
	// collector → pg, collector → pg-2, pg-2 → pg, pg → mon, pg-2 → mon.
	// (caller → callee = caller depends on callee)
	nodes := []model.TopoNode{
		{ID: "collector"}, {ID: "pg"}, {ID: "pg2"}, {ID: "mon"},
		{ID: "internet", External: true},
	}
	edge := func(s, d string) model.TopoEdge { return model.TopoEdge{Src: s, Dst: d, Internal: true} }
	edges := []model.TopoEdge{
		edge("collector", "pg"), edge("collector", "pg2"),
		edge("pg2", "pg"), edge("pg", "mon"), edge("pg2", "mon"),
		{Src: "collector", Dst: "internet"}, // external, must be ignored
	}

	computeImpact(nodes, edges)
	imp := map[string]int{}
	spof := map[string]bool{}
	for _, n := range nodes {
		imp[n.ID] = n.ImpactCount
		spof[n.ID] = n.SPOF
	}

	// mon: everything reaches it (collector→pg→mon, collector→pg2→mon, pg2→mon, pg→mon) = collector,pg,pg2 = 3
	if imp["mon"] != 3 {
		t.Errorf("impact[mon] = %d, want 3", imp["mon"])
	}
	// pg: collector (→pg), pg2 (→pg), and collector via pg2 = collector,pg2 = 2
	if imp["pg"] != 2 {
		t.Errorf("impact[pg] = %d, want 2 (collector, pg2)", imp["pg"])
	}
	// pg2: only collector depends on it
	if imp["pg2"] != 1 {
		t.Errorf("impact[pg2] = %d, want 1 (collector)", imp["pg2"])
	}
	// collector: nothing depends on it (leaf)
	if imp["collector"] != 0 {
		t.Errorf("impact[collector] = %d, want 0", imp["collector"])
	}
	// threshold = max(2, 4/2)=2 → mon (3) and pg (2) are SPOFs; pg2 (1), collector (0) are not
	if !spof["mon"] || !spof["pg"] {
		t.Errorf("mon and pg should be SPOFs: mon=%v pg=%v", spof["mon"], spof["pg"])
	}
	if spof["pg2"] || spof["collector"] {
		t.Errorf("pg2/collector should not be SPOFs: pg2=%v collector=%v", spof["pg2"], spof["collector"])
	}
	// external node never gets impact/SPOF
	if imp["internet"] != 0 || spof["internet"] {
		t.Errorf("external node must have no impact/SPOF")
	}
}
