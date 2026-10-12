package store

import (
	"context"
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestOTLPServiceHealth(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// 4 root requests for "api": 1 error, latencies 10/20/30/40ms. Plus a child
	// span (parent set) that must NOT count as a request.
	ms := int64(1_000_000)
	spans := []model.OTLPSpan{
		{TraceID: "t1", SpanID: "a", Service: "api", DurNs: 10 * ms, Status: "ok", TS: 100},
		{TraceID: "t2", SpanID: "b", Service: "api", DurNs: 20 * ms, Status: "ok", TS: 100},
		{TraceID: "t3", SpanID: "c", Service: "api", DurNs: 30 * ms, Status: "ok", TS: 100},
		{TraceID: "t4", SpanID: "d", Service: "api", DurNs: 40 * ms, Status: "error", TS: 100},
		{TraceID: "t4", SpanID: "e", ParentID: "d", Service: "api", DurNs: 5 * ms, Status: "ok", TS: 100},
	}
	if err := s.InsertOTLPSpans(ctx, model.DefaultOrg, spans); err != nil {
		t.Fatal(err)
	}

	out, err := s.OTLPServiceHealth(ctx, nil, 0, 10) // 10-minute window
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d services, want 1", len(out))
	}
	h := out[0]
	if h.Service != "api" {
		t.Fatalf("service = %q", h.Service)
	}
	if h.Requests != 4 {
		t.Errorf("requests = %d, want 4 (child span excluded)", h.Requests)
	}
	if h.Errors != 1 || h.ErrorRate != 0.25 {
		t.Errorf("errors=%d rate=%.2f, want 1 / 0.25", h.Errors, h.ErrorRate)
	}
	if h.ReqPerMin != 0.4 { // 4 reqs / 10 min
		t.Errorf("req/min = %.2f, want 0.4", h.ReqPerMin)
	}
	// nearest-rank on [10,20,30,40]: p50→idx1=20, p95/p99→idx3=40.
	if h.P50Ms != 20 || h.P99Ms != 40 {
		t.Errorf("p50=%.0f p99=%.0f, want 20 / 40", h.P50Ms, h.P99Ms)
	}
}
