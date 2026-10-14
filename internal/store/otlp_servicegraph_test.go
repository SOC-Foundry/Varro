package store

import (
	"context"
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestOTLPServiceGraph(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	ms := int64(1_000_000)
	// Two traces. Shape per trace: gateway(root) → api → db, and api also calls
	// cache. In trace t2 the db call errors.
	//   gateway -> api   : 2 calls
	//   api -> db        : 2 calls (1 error in t2), latencies 30/50ms
	//   api -> cache     : 1 call
	// The api->api internal span (same service as parent) must NOT make an edge.
	spans := []model.OTLPSpan{
		// t1
		{TraceID: "t1", SpanID: "g1", Service: "gateway", DurNs: 100 * ms, Status: "ok", TS: 100},
		{TraceID: "t1", SpanID: "a1", ParentID: "g1", Service: "api", DurNs: 80 * ms, Status: "ok", TS: 100},
		{TraceID: "t1", SpanID: "a1i", ParentID: "a1", Service: "api", DurNs: 10 * ms, Status: "ok", TS: 100}, // internal
		{TraceID: "t1", SpanID: "d1", ParentID: "a1", Service: "db", DurNs: 30 * ms, Status: "ok", TS: 100},
		{TraceID: "t1", SpanID: "c1", ParentID: "a1", Service: "cache", DurNs: 2 * ms, Status: "ok", TS: 100},
		// t2
		{TraceID: "t2", SpanID: "g2", Service: "gateway", DurNs: 120 * ms, Status: "ok", TS: 100},
		{TraceID: "t2", SpanID: "a2", ParentID: "g2", Service: "api", DurNs: 90 * ms, Status: "ok", TS: 100},
		{TraceID: "t2", SpanID: "d2", ParentID: "a2", Service: "db", DurNs: 50 * ms, Status: "error", TS: 100},
	}
	if err := s.InsertOTLPSpans(ctx, model.DefaultOrg, spans); err != nil {
		t.Fatal(err)
	}

	g, err := s.OTLPServiceGraph(ctx, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	edge := func(caller, callee string) *model.ServiceEdge {
		for i := range g.Edges {
			if g.Edges[i].Caller == caller && g.Edges[i].Callee == callee {
				return &g.Edges[i]
			}
		}
		return nil
	}

	if len(g.Edges) != 3 {
		t.Fatalf("got %d edges, want 3 (gateway→api, api→db, api→cache); internal api→api excluded: %+v", len(g.Edges), g.Edges)
	}
	if e := edge("gateway", "api"); e == nil || e.Calls != 2 {
		t.Errorf("gateway→api = %+v, want 2 calls", e)
	}
	if e := edge("api", "db"); e == nil || e.Calls != 2 || e.Errors != 1 || e.ErrorRate != 0.5 {
		t.Errorf("api→db = %+v, want 2 calls / 1 error / 0.5", e)
	} else if e.P50Ms != 30 { // nearest-rank p50 on [30,50]: ceil(0.5*2)-1 = idx0 = 30
		t.Errorf("api→db p50 = %.0f, want 30", e.P50Ms)
	}
	if e := edge("api", "cache"); e == nil || e.Calls != 1 {
		t.Errorf("api→cache = %+v, want 1 call", e)
	}

	node := func(name string) *model.ServiceNode {
		for i := range g.Nodes {
			if g.Nodes[i].Service == name {
				return &g.Nodes[i]
			}
		}
		return nil
	}
	if len(g.Nodes) != 4 {
		t.Fatalf("got %d nodes, want 4 (gateway, api, db, cache): %+v", len(g.Nodes), g.Nodes)
	}
	if n := node("gateway"); n == nil || !n.Root || n.Outgoing != 2 || n.Incoming != 0 {
		t.Errorf("gateway node = %+v, want root, out=2, in=0", n)
	}
	if n := node("api"); n == nil || n.Incoming != 2 || n.Outgoing != 3 {
		t.Errorf("api node = %+v, want in=2 out=3", n)
	}
	if n := node("db"); n == nil || n.Incoming != 2 || n.Errors != 1 {
		t.Errorf("db node = %+v, want in=2 errors=1", n)
	}
}
