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
type otlpAttr struct {
	Key   string `json:"key"`
	Value struct {
		StringValue *string  `json:"stringValue"`
		IntValue    *string  `json:"intValue"` // int64 serialized as string
		DoubleValue *float64 `json:"doubleValue"`
		BoolValue   *bool    `json:"boolValue"`
	} `json:"value"`
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

func attrString(a otlpAttr) string {
	switch {
	case a.Value.StringValue != nil:
		return *a.Value.StringValue
	case a.Value.IntValue != nil:
		return *a.Value.IntValue
	case a.Value.DoubleValue != nil:
		return strconv.FormatFloat(*a.Value.DoubleValue, 'g', -1, 64)
	case a.Value.BoolValue != nil:
		return strconv.FormatBool(*a.Value.BoolValue)
	}
	return ""
}

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
