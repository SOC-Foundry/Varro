package store

import (
	"context"
	"math"
	"sort"

	"github.com/soc-foundry/varro/internal/model"
)

// InsertOTLPMetrics stores a batch of OTLP data points for one org.
func (s *Store) InsertOTLPMetrics(ctx context.Context, orgID string, pts []model.OTLPMetric) error {
	if len(pts) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ins, err := tx.PrepareContext(ctx,
		`INSERT INTO otlp_metrics (org_id, service, metric, ts, value, attrs) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer ins.Close()
	for _, p := range pts {
		if p.Metric == "" {
			continue
		}
		if _, err := ins.ExecContext(ctx, orgID, p.Service, p.Metric, p.TS, p.Value, p.Attrs); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// InsertOTLPSpans stores a batch of trace spans for one org.
func (s *Store) InsertOTLPSpans(ctx context.Context, orgID string, spans []model.OTLPSpan) error {
	if len(spans) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ins, err := tx.PrepareContext(ctx, `
INSERT INTO otlp_spans (org_id, trace_id, span_id, parent_id, service, name, kind, start_ns, dur_ns, status, attrs, ts)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer ins.Close()
	for _, sp := range spans {
		if sp.TraceID == "" || sp.SpanID == "" {
			continue
		}
		if _, err := ins.ExecContext(ctx, orgID, sp.TraceID, sp.SpanID, sp.ParentID, sp.Service,
			sp.Name, sp.Kind, sp.StartNs, sp.DurNs, sp.Status, sp.Attrs, sp.TS); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// OTLPTraces returns recent traces (newest first) rolled up from their spans.
func (s *Store) OTLPTraces(ctx context.Context, orgIDs []string, since int64, limit int) ([]model.OTLPTraceSummary, error) {
	filter, args := orgFilter("org_id", orgIDs)
	args = append([]any{since}, args...)
	// Bounded span fetch; group into traces in Go for dialect portability.
	rows, err := s.db.QueryContext(ctx, `
SELECT trace_id, parent_id, service, name, start_ns, dur_ns, status FROM otlp_spans
WHERE ts >= ?`+filter+`
ORDER BY start_ns DESC
LIMIT 20000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type acc struct {
		sum      *model.OTLPTraceSummary
		minStart int64
		maxEnd   int64
	}
	traces := map[string]*acc{}
	var order []string
	for rows.Next() {
		var traceID, parent, service, name, status string
		var start, dur int64
		if err := rows.Scan(&traceID, &parent, &service, &name, &start, &dur, &status); err != nil {
			return nil, err
		}
		a := traces[traceID]
		if a == nil {
			a = &acc{sum: &model.OTLPTraceSummary{TraceID: traceID}, minStart: start, maxEnd: start + dur}
			traces[traceID] = a
			order = append(order, traceID)
		}
		a.sum.SpanCount++
		if status == "error" {
			a.sum.Error = true
		}
		if start < a.minStart {
			a.minStart = start
		}
		if start+dur > a.maxEnd {
			a.maxEnd = start + dur
		}
		// Root span (no parent) names the trace and its service.
		if parent == "" {
			a.sum.Operation = name
			a.sum.Service = service
		}
		if a.sum.Service == "" {
			a.sum.Service = service
		}
		if a.sum.Operation == "" {
			a.sum.Operation = name
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]model.OTLPTraceSummary, 0, len(order))
	for _, id := range order {
		a := traces[id]
		a.sum.StartTS = a.minStart / 1_000_000_000
		a.sum.DurationMs = float64(a.maxEnd-a.minStart) / 1_000_000
		out = append(out, *a.sum)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// OTLPServiceHealth computes per-service RED metrics (request rate, error rate,
// latency percentiles) from root spans in the window. Aggregated in Go.
func (s *Store) OTLPServiceHealth(ctx context.Context, orgIDs []string, since int64, minutes int) ([]model.ServiceHealth, error) {
	filter, args := orgFilter("org_id", orgIDs)
	args = append([]any{since}, args...)
	rows, err := s.db.QueryContext(ctx, `
SELECT service, dur_ns, status FROM otlp_spans
WHERE parent_id = '' AND ts >= ?`+filter+`
LIMIT 100000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type acc struct {
		durs   []float64 // ms
		errors int
	}
	svc := map[string]*acc{}
	var order []string
	for rows.Next() {
		var service, status string
		var dur int64
		if err := rows.Scan(&service, &dur, &status); err != nil {
			return nil, err
		}
		a := svc[service]
		if a == nil {
			a = &acc{}
			svc[service] = a
			order = append(order, service)
		}
		a.durs = append(a.durs, float64(dur)/1e6)
		if status == "error" {
			a.errors++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if minutes < 1 {
		minutes = 1
	}
	out := make([]model.ServiceHealth, 0, len(order))
	for _, name := range order {
		a := svc[name]
		sort.Float64s(a.durs)
		n := len(a.durs)
		out = append(out, model.ServiceHealth{
			Service:   name,
			Requests:  n,
			Errors:    a.errors,
			ErrorRate: float64(a.errors) / float64(n),
			ReqPerMin: float64(n) / float64(minutes),
			P50Ms:     pctl(a.durs, 0.50),
			P95Ms:     pctl(a.durs, 0.95),
			P99Ms:     pctl(a.durs, 0.99),
		})
	}
	// Busiest services first.
	sort.Slice(out, func(i, j int) bool { return out[i].Requests > out[j].Requests })
	return out, nil
}

// pctl returns the q-quantile (0..1) of a pre-sorted slice using the nearest-
// rank method (ceil(q*n)), so high percentiles approach the max even for small n.
func pctl(sorted []float64, q float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	i := int(math.Ceil(q*float64(n))) - 1
	if i < 0 {
		i = 0
	}
	if i >= n {
		i = n - 1
	}
	return sorted[i]
}

// OTLPTraceSpans returns one trace's spans, earliest first (for the detail view).
func (s *Store) OTLPTraceSpans(ctx context.Context, orgIDs []string, traceID string) ([]model.OTLPSpan, error) {
	filter, args := orgFilter("org_id", orgIDs)
	args = append([]any{traceID}, args...)
	rows, err := s.db.QueryContext(ctx, `
SELECT trace_id, span_id, parent_id, service, name, kind, start_ns, dur_ns, status, attrs
FROM otlp_spans WHERE trace_id = ?`+filter+`
ORDER BY start_ns`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.OTLPSpan
	for rows.Next() {
		var sp model.OTLPSpan
		if err := rows.Scan(&sp.TraceID, &sp.SpanID, &sp.ParentID, &sp.Service, &sp.Name,
			&sp.Kind, &sp.StartNs, &sp.DurNs, &sp.Status, &sp.Attrs); err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

// OTLPSummaries rolls up service+metric over the window (since unix seconds):
// point count and latest value. Aggregated in Go for dialect portability.
func (s *Store) OTLPSummaries(ctx context.Context, orgIDs []string, since int64) ([]model.OTLPMetricSummary, error) {
	filter, args := orgFilter("org_id", orgIDs)
	args = append([]any{since}, args...)
	rows, err := s.db.QueryContext(ctx, `
SELECT service, metric, ts, value FROM otlp_metrics
WHERE ts >= ?`+filter+`
ORDER BY ts
LIMIT 100000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type key struct{ svc, met string }
	agg := map[key]*model.OTLPMetricSummary{}
	var order []key
	for rows.Next() {
		var svc, met string
		var ts int64
		var val float64
		if err := rows.Scan(&svc, &met, &ts, &val); err != nil {
			return nil, err
		}
		k := key{svc, met}
		a := agg[k]
		if a == nil {
			a = &model.OTLPMetricSummary{Service: svc, Metric: met}
			agg[k] = a
			order = append(order, k)
		}
		a.Count++
		if ts >= a.LastTS { // rows are ts-ascending, so last wins
			a.LastTS, a.LastValue = ts, val
		}
	}
	out := make([]model.OTLPMetricSummary, 0, len(order))
	for _, k := range order {
		out = append(out, *agg[k])
	}
	return out, rows.Err()
}
