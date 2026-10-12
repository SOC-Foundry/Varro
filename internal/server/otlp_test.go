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
