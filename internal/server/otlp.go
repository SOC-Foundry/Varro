package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

const maxOTLPBody = 16 << 20

// otlpOrg resolves the org an OTLP push belongs to from its bearer token: the
// master token maps to the default org, an org enrollment token to its org.
func (s *Server) otlpOrg(r *http.Request) (string, bool) {
	if s.masterAuthorized(r) {
		return model.DefaultOrg, true
	}
	tok := bearer(r)
	if tok == "" {
		return "", false
	}
	if org, err := s.store.OrgForTokenHash(r.Context(), hashToken(tok)); err == nil && org != "" {
		return org, true
	}
	return "", false
}

// OTLP/HTTP JSON shapes — a minimal subset of ExportMetricsServiceRequest
// (gauge + sum numeric data points). https://opentelemetry.io/docs/specs/otlp/
type otlpValue struct {
	StringValue *string  `json:"stringValue"`
	IntValue    *string  `json:"intValue"` // int64 serialized as string
	DoubleValue *float64 `json:"doubleValue"`
	BoolValue   *bool    `json:"boolValue"`
}

type otlpAttr struct {
	Key   string    `json:"key"`
	Value otlpValue `json:"value"`
}

type otlpPoint struct {
	TimeUnixNano string     `json:"timeUnixNano"`
	AsDouble     *float64   `json:"asDouble"`
	AsInt        *string    `json:"asInt"` // int64 serialized as string
	Attributes   []otlpAttr `json:"attributes"`
}

type otlpStream struct {
	DataPoints []otlpPoint `json:"dataPoints"`
}

type otlpMetricsReq struct {
	ResourceMetrics []struct {
		Resource struct {
			Attributes []otlpAttr `json:"attributes"`
		} `json:"resource"`
		ScopeMetrics []struct {
			Metrics []struct {
				Name  string      `json:"name"`
				Gauge *otlpStream `json:"gauge"`
				Sum   *otlpStream `json:"sum"`
			} `json:"metrics"`
		} `json:"scopeMetrics"`
	} `json:"resourceMetrics"`
}

func valueString(v otlpValue) string {
	switch {
	case v.StringValue != nil:
		return *v.StringValue
	case v.IntValue != nil:
		return *v.IntValue
	case v.DoubleValue != nil:
		return strconv.FormatFloat(*v.DoubleValue, 'g', -1, 64)
	case v.BoolValue != nil:
		return strconv.FormatBool(*v.BoolValue)
	}
	return ""
}

func attrString(a otlpAttr) string { return valueString(a.Value) }

func pointValue(p otlpPoint) (float64, bool) {
	if p.AsDouble != nil {
		return *p.AsDouble, true
	}
	if p.AsInt != nil {
		if v, err := strconv.ParseInt(*p.AsInt, 10, 64); err == nil {
			return float64(v), true
		}
	}
	return 0, false
}

// handleOTLPMetrics is an OTLP/HTTP (JSON) metrics receiver at /v1/metrics. Apps
// point their OpenTelemetry exporter here (OTEL_EXPORTER_OTLP_PROTOCOL=http/json)
// with a Varro token to push custom app/API metrics into Varro.
func (s *Server) handleOTLPMetrics(w http.ResponseWriter, r *http.Request) {
	org, ok := s.otlpOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.Contains(ct, "json") {
		http.Error(w, "send OTLP/HTTP JSON (set OTEL_EXPORTER_OTLP_PROTOCOL=http/json); protobuf not supported", http.StatusUnsupportedMediaType)
		return
	}
	var req otlpMetricsReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxOTLPBody)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	var pts []model.OTLPMetric
	for _, rm := range req.ResourceMetrics {
		service := ""
		for _, a := range rm.Resource.Attributes {
			if a.Key == "service.name" {
				service = attrString(a)
			}
		}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				for _, stream := range []*otlpStream{m.Gauge, m.Sum} {
					if stream == nil {
						continue
					}
					for _, dp := range stream.DataPoints {
						val, ok := pointValue(dp)
						if !ok {
							continue
						}
						ts := time.Now().Unix()
						if dp.TimeUnixNano != "" {
							if ns, err := strconv.ParseInt(dp.TimeUnixNano, 10, 64); err == nil && ns > 0 {
								ts = ns / 1_000_000_000
							}
						}
						var attrs []string
						for _, a := range dp.Attributes {
							attrs = append(attrs, a.Key+"="+attrString(a))
						}
						pts = append(pts, model.OTLPMetric{
							Service: service, Metric: m.Name, TS: ts, Value: val,
							Attrs: strings.Join(attrs, ","),
						})
					}
				}
			}
		}
	}
	if err := s.store.InsertOTLPMetrics(r.Context(), org, pts); err != nil {
		s.log.Error("otlp ingest failed", "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	// OTLP success response is an empty JSON ExportMetricsServiceResponse.
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{}"))
}

// OTLP/HTTP JSON trace shapes — a subset of ExportTraceServiceRequest.
type otlpSpanJSON struct {
	TraceID           string     `json:"traceId"`
	SpanID            string     `json:"spanId"`
	ParentSpanID      string     `json:"parentSpanId"`
	Name              string     `json:"name"`
	Kind              int        `json:"kind"`
	StartTimeUnixNano string     `json:"startTimeUnixNano"`
	EndTimeUnixNano   string     `json:"endTimeUnixNano"`
	Attributes        []otlpAttr `json:"attributes"`
	Status            struct {
		Code int `json:"code"` // 0 unset, 1 ok, 2 error
	} `json:"status"`
}

type otlpTracesReq struct {
	ResourceSpans []struct {
		Resource struct {
			Attributes []otlpAttr `json:"attributes"`
		} `json:"resource"`
		ScopeSpans []struct {
			Spans []otlpSpanJSON `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

var spanKindName = map[int]string{1: "internal", 2: "server", 3: "client", 4: "producer", 5: "consumer"}

// handleOTLPTraces is an OTLP/HTTP (JSON) trace receiver at /v1/traces.
func (s *Server) handleOTLPTraces(w http.ResponseWriter, r *http.Request) {
	org, ok := s.otlpOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.Contains(ct, "json") {
		http.Error(w, "send OTLP/HTTP JSON (set OTEL_EXPORTER_OTLP_PROTOCOL=http/json); protobuf not supported", http.StatusUnsupportedMediaType)
		return
	}
	var req otlpTracesReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxOTLPBody)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	var spans []model.OTLPSpan
	for _, rs := range req.ResourceSpans {
		service := ""
		for _, a := range rs.Resource.Attributes {
			if a.Key == "service.name" {
				service = attrString(a)
			}
		}
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				start, _ := strconv.ParseInt(sp.StartTimeUnixNano, 10, 64)
				end, _ := strconv.ParseInt(sp.EndTimeUnixNano, 10, 64)
				dur := end - start
				if dur < 0 {
					dur = 0
				}
				status := ""
				if sp.Status.Code == 2 {
					status = "error"
				} else if sp.Status.Code == 1 {
					status = "ok"
				}
				var attrs []string
				for _, a := range sp.Attributes {
					attrs = append(attrs, a.Key+"="+attrString(a))
				}
				spans = append(spans, model.OTLPSpan{
					TraceID: sp.TraceID, SpanID: sp.SpanID, ParentID: sp.ParentSpanID,
					Service: service, Name: sp.Name, Kind: spanKindName[sp.Kind],
					StartNs: start, DurNs: dur, Status: status,
					Attrs: strings.Join(attrs, ","), TS: start / 1_000_000_000,
				})
			}
		}
	}
	if err := s.store.InsertOTLPSpans(r.Context(), org, spans); err != nil {
		s.log.Error("otlp traces ingest failed", "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{}"))
}

// handleOTLPTraceList serves recent traces (read-scoped).
func (s *Server) handleOTLPTraceList(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	minutes := 60
	if v, err := strconv.Atoi(r.URL.Query().Get("minutes")); err == nil && v > 0 && v <= 10080 {
		minutes = v
	}
	since := time.Now().Add(-time.Duration(minutes) * time.Minute).Unix()
	traces, err := s.store.OTLPTraces(r.Context(), scope, since, 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if traces == nil {
		traces = []model.OTLPTraceSummary{}
	}
	writeJSON(w, map[string]any{"minutes": minutes, "traces": traces})
}

// handleOTLPTraceDetail serves one trace's spans (read-scoped).
func (s *Server) handleOTLPTraceDetail(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	spans, err := s.store.OTLPTraceSpans(r.Context(), scope, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if spans == nil {
		spans = []model.OTLPSpan{}
	}
	writeJSON(w, map[string]any{"spans": spans})
}

// OTLP/HTTP JSON log shapes — a subset of ExportLogsServiceRequest.
type otlpLogsReq struct {
	ResourceLogs []struct {
		Resource struct {
			Attributes []otlpAttr `json:"attributes"`
		} `json:"resource"`
		ScopeLogs []struct {
			Scope struct {
				Name string `json:"name"`
			} `json:"scope"`
			LogRecords []struct {
				TimeUnixNano   string    `json:"timeUnixNano"`
				SeverityNumber int       `json:"severityNumber"`
				SeverityText   string    `json:"severityText"`
				Body           otlpValue `json:"body"`
			} `json:"logRecords"`
		} `json:"scopeLogs"`
	} `json:"resourceLogs"`
}

// otlpLogSeverity normalizes OTLP severity (text or 1-24 number) to the names
// the logs pillar uses, so OTLP app logs filter alongside journald logs.
func otlpLogSeverity(text string, num int) string {
	switch strings.ToUpper(text) {
	case "FATAL", "CRITICAL":
		return "critical"
	case "ERROR", "ERR":
		return "error"
	case "WARN", "WARNING":
		return "warning"
	case "NOTICE":
		return "notice"
	case "INFO":
		return "info"
	case "DEBUG", "TRACE":
		return "debug"
	}
	switch {
	case num >= 21:
		return "critical"
	case num >= 17:
		return "error"
	case num >= 13:
		return "warning"
	case num >= 9:
		return "info"
	case num >= 1:
		return "debug"
	}
	return ""
}

// handleOTLPLogs is an OTLP/HTTP (JSON) log receiver at /v1/logs. App logs land
// in the same logs pillar as journald (endpoint id "otlp/<service>"), so they
// search/filter/tail in the existing Logs view.
func (s *Server) handleOTLPLogs(w http.ResponseWriter, r *http.Request) {
	org, ok := s.otlpOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.Contains(ct, "json") {
		http.Error(w, "send OTLP/HTTP JSON (set OTEL_EXPORTER_OTLP_PROTOCOL=http/json); protobuf not supported", http.StatusUnsupportedMediaType)
		return
	}
	var req otlpLogsReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxOTLPBody)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Group by pseudo-endpoint (otlp/<service>) so one InsertLogs call per source.
	byEP := map[string][]model.LogEntry{}
	for _, rl := range req.ResourceLogs {
		service := "unknown"
		for _, a := range rl.Resource.Attributes {
			if a.Key == "service.name" {
				if v := attrString(a); v != "" {
					service = v
				}
			}
		}
		ep := "otlp/" + service
		for _, sl := range rl.ScopeLogs {
			for _, lr := range sl.LogRecords {
				msg := valueString(lr.Body)
				if msg == "" {
					continue
				}
				ts := time.Now().Unix()
				if lr.TimeUnixNano != "" {
					if ns, err := strconv.ParseInt(lr.TimeUnixNano, 10, 64); err == nil && ns > 0 {
						ts = ns / 1_000_000_000
					}
				}
				byEP[ep] = append(byEP[ep], model.LogEntry{
					TS:       ts,
					Severity: otlpLogSeverity(lr.SeverityText, lr.SeverityNumber),
					Source:   sl.Scope.Name,
					Message:  msg,
				})
			}
		}
	}
	for ep, entries := range byEP {
		if err := s.store.InsertLogs(r.Context(), org, ep, entries); err != nil {
			s.log.Error("otlp logs ingest failed", "error", err)
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{}"))
}

// handleOTLPList serves the custom-metrics rollup (read-scoped).
func (s *Server) handleOTLPList(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	minutes := 60
	if v, err := strconv.Atoi(r.URL.Query().Get("minutes")); err == nil && v > 0 && v <= 10080 {
		minutes = v
	}
	since := time.Now().Add(-time.Duration(minutes) * time.Minute).Unix()
	out, err := s.store.OTLPSummaries(r.Context(), scope, since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if out == nil {
		out = []model.OTLPMetricSummary{}
	}
	writeJSON(w, map[string]any{"minutes": minutes, "metrics": out})
}
