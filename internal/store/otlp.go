package store

import (
	"context"

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
