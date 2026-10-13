package store

import (
	"context"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// SearchEvents returns events matching a text substring (on message) and/or type,
// newest-first, scoped to orgs. Zero-value filters are ignored.
func (s *Store) SearchEvents(ctx context.Context, orgIDs []string, text, typ string, since int64, limit int) ([]model.StoredEvent, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	filter, args := orgFilter("ev.org_id", orgIDs)
	q := `
SELECT ev.id, ev.org_id, ev.endpoint_id, COALESCE(e.hostname, ev.endpoint_id), ev.ts, ev.type, ev.message
FROM events ev LEFT JOIN endpoints e ON e.id = ev.endpoint_id
WHERE 1=1` + filter
	if typ != "" {
		q += ` AND ev.type = ?`
		args = append(args, typ)
	}
	if since > 0 {
		q += ` AND ev.ts >= ?`
		args = append(args, since)
	}
	if text != "" {
		q += ` AND ev.message LIKE ?`
		args = append(args, "%"+text+"%")
	}
	q += ` ORDER BY ev.ts DESC, ev.id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.StoredEvent
	for rows.Next() {
		var ev model.StoredEvent
		var ts int64
		if err := rows.Scan(&ev.ID, &ev.OrgID, &ev.EndpointID, &ev.Hostname, &ts, &ev.Type, &ev.Message); err != nil {
			return nil, err
		}
		ev.Timestamp = time.Unix(ts, 0).UTC()
		out = append(out, ev)
	}
	return out, rows.Err()
}

// ---- saved hunts ----

func (s *Store) SaveHunt(ctx context.Context, owner, orgID string, h model.Hunt) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM hunts WHERE owner = ? AND name = ?`, owner, h.Name); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO hunts (owner, org_id, name, query, source, severity, alerting, threshold, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		owner, orgID, h.Name, h.Query, h.Source, h.Severity, b2i(h.Alerting), h.Threshold, time.Now().Unix())
	return err
}

func (s *Store) ListHunts(ctx context.Context, owner string) ([]model.Hunt, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, query, source, severity, alerting, threshold, created_at FROM hunts WHERE owner = ? ORDER BY name`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanHunts(rows)
}

// AlertingHunts returns every hunt flagged for alerting (across owners/orgs) for
// the leader's evaluation loop.
func (s *Store) AlertingHunts(ctx context.Context) ([]model.Hunt, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, org_id, name, query, source, severity, alerting, threshold, created_at FROM hunts WHERE alerting = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Hunt
	for rows.Next() {
		var h model.Hunt
		var alerting int
		var created int64
		if err := rows.Scan(&h.ID, &h.OrgID, &h.Name, &h.Query, &h.Source, &h.Severity, &alerting, &h.Threshold, &created); err != nil {
			return nil, err
		}
		h.Alerting = alerting != 0
		h.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) DeleteHunt(ctx context.Context, owner string, id int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM hunts WHERE owner = ? AND id = ?`, owner, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func scanHunts(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]model.Hunt, error) {
	var out []model.Hunt
	for rows.Next() {
		var h model.Hunt
		var alerting int
		var created int64
		if err := rows.Scan(&h.ID, &h.Name, &h.Query, &h.Source, &h.Severity, &alerting, &h.Threshold, &created); err != nil {
			return nil, err
		}
		h.Alerting = alerting != 0
		h.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, h)
	}
	return out, rows.Err()
}
