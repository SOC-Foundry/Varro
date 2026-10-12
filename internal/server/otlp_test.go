package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

const otlpBody = `{"resourceMetrics":[{"resource":{"attributes":[
  {"key":"service.name","value":{"stringValue":"checkout"}}]},
 "scopeMetrics":[{"metrics":[
  {"name":"http.server.requests","sum":{"dataPoints":[
    {"timeUnixNano":"1700000000000000000","asInt":"42","attributes":[{"key":"route","value":{"stringValue":"/pay"}}]}]}},
  {"name":"http.server.latency_ms","gauge":{"dataPoints":[{"asDouble":12.5}]}}
 ]}]}]}`

func TestOTLPMetricsIngest(t *testing.T) {
	srv, st := newTestServer(t)

	r := httptest.NewRequest("POST", "/v1/metrics", strings.NewReader(otlpBody))
	r.Header.Set("Authorization", "Bearer master-secret")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleOTLPMetrics(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}

	sums, err := st.OTLPSummaries(context.Background(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(sums) != 2 {
		t.Fatalf("got %d metric streams, want 2", len(sums))
	}
	got := map[string]float64{}
	for _, s := range sums {
		if s.Service != "checkout" {
			t.Errorf("service = %q, want checkout", s.Service)
		}
		got[s.Metric] = s.LastValue
	}
	if got["http.server.requests"] != 42 {
		t.Errorf("requests (sum/asInt) = %v, want 42", got["http.server.requests"])
	}
	if got["http.server.latency_ms"] != 12.5 {
		t.Errorf("latency (gauge/asDouble) = %v, want 12.5", got["http.server.latency_ms"])
	}
}

const otlpTracesBody = `{"resourceSpans":[{"resource":{"attributes":[
  {"key":"service.name","value":{"stringValue":"gateway"}}]},
 "scopeSpans":[{"spans":[
  {"traceId":"abc123","spanId":"root","name":"GET /checkout","kind":2,
   "startTimeUnixNano":"1700000000000000000","endTimeUnixNano":"1700000000150000000","status":{"code":1}},
  {"traceId":"abc123","spanId":"child","parentSpanId":"root","name":"db.query","kind":3,
   "startTimeUnixNano":"1700000000020000000","endTimeUnixNano":"1700000000090000000","status":{"code":2}}
 ]}]}]}`

func TestOTLPTracesIngest(t *testing.T) {
	srv, st := newTestServer(t)

	r := httptest.NewRequest("POST", "/v1/traces", strings.NewReader(otlpTracesBody))
	r.Header.Set("Authorization", "Bearer master-secret")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleOTLPTraces(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}

	traces, err := st.OTLPTraces(context.Background(), nil, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(traces) != 1 {
		t.Fatalf("got %d traces, want 1", len(traces))
	}
	tr := traces[0]
	if tr.Operation != "GET /checkout" || tr.Service != "gateway" {
		t.Errorf("root op/service wrong: %+v", tr)
	}
	if tr.SpanCount != 2 {
		t.Errorf("span count = %d, want 2", tr.SpanCount)
	}
	if !tr.Error {
		t.Errorf("trace should be flagged error (child span status=error)")
	}
	if tr.DurationMs != 150 { // root span 0..150ms wall clock
		t.Errorf("duration = %v ms, want 150", tr.DurationMs)
	}
	// Detail returns both spans, earliest first.
	spans, err := st.OTLPTraceSpans(context.Background(), nil, "abc123")
	if err != nil || len(spans) != 2 {
		t.Fatalf("trace spans: n=%d err=%v", len(spans), err)
	}
	if spans[0].SpanID != "root" {
		t.Errorf("spans not start-ordered: %+v", spans)
	}
}

func TestOTLPMetricsAuthAndContentType(t *testing.T) {
	srv, _ := newTestServer(t)

	// No token -> 401.
	r := httptest.NewRequest("POST", "/v1/metrics", strings.NewReader(otlpBody))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleOTLPMetrics(w, r)
	if w.Code != 401 {
		t.Fatalf("no-token status = %d, want 401", w.Code)
	}

	// Protobuf content-type -> 415.
	r = httptest.NewRequest("POST", "/v1/metrics", strings.NewReader("\x00"))
	r.Header.Set("Authorization", "Bearer master-secret")
	r.Header.Set("Content-Type", "application/x-protobuf")
	w = httptest.NewRecorder()
	srv.handleOTLPMetrics(w, r)
	if w.Code != 415 {
		t.Fatalf("protobuf status = %d, want 415", w.Code)
	}
}
