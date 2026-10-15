package server

import (
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestResolveCalleeProcesses(t *testing.T) {
	// db-01 listens: postgres on 5432, redis on 6379. web-01 listens: nginx:443.
	snaps := map[string]*model.Snapshot{
		"db-01": {Security: model.SecurityMetrics{ListeningPorts: []model.ListeningPort{
			{Port: 5432, Process: "postgres"},
			{Port: 6379, Process: "redis"},
		}}},
		"web-01": {Security: model.SecurityMetrics{ListeningPorts: []model.ListeningPort{
			{Port: 443, Process: "nginx"},
		}}},
		"blank-02": nil, // nil snapshot must not panic
	}
	edges := []model.TopoEdge{
		{Src: "web-01", Dst: "db-01", Internal: true, Processes: []model.EdgeProcess{
			{Process: "nginx", Port: 5432}, // → postgres
			{Process: "nginx", Port: 6379}, // → redis
			{Process: "nginx", Port: 9999}, // no listener known → stays empty
		}},
		{Src: "web-01", Dst: "blank-02", Internal: true, Processes: []model.EdgeProcess{
			{Process: "nginx", Port: 80},
		}},
		{Src: "web-01", Dst: "internet", Internal: false, Processes: []model.EdgeProcess{
			{Process: "curl", Port: 443}, // external edge must be untouched
		}},
	}

	resolveCalleeProcesses(edges, snaps)

	if got := edges[0].Processes[0].DstProcess; got != "postgres" {
		t.Errorf("edge0 proc0 DstProcess = %q, want postgres", got)
	}
	if got := edges[0].Processes[1].DstProcess; got != "redis" {
		t.Errorf("edge0 proc1 DstProcess = %q, want redis", got)
	}
	if got := edges[0].Processes[2].DstProcess; got != "" {
		t.Errorf("edge0 proc2 DstProcess = %q, want empty (no listener on 9999)", got)
	}
	if got := edges[1].Processes[0].DstProcess; got != "" {
		t.Errorf("edge to nil-snapshot dst should stay empty, got %q", got)
	}
	if got := edges[2].Processes[0].DstProcess; got != "" {
		t.Errorf("external edge must be untouched, got %q", got)
	}
}
