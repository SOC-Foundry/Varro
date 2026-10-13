package store

import (
	"context"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// SaveDashboard stores (or replaces, by owner+name) a multi-panel dashboard.
func (s *Store) SaveDashboard(ctx context.Context, owner, orgID, name, spec string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM dashboards WHERE owner = ? AND name = ?`, owner, name); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO dashboards (owner, org_id, name, spec, created_at) VALUES (?, ?, ?, ?, ?)`,
		owner, orgID, name, spec, time.Now().Unix())
	return err
}

// ListDashboards returns an owner's dashboards, by name.
func (s *Store) ListDashboards(ctx context.Context, owner string) ([]model.Dashboard, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, spec, created_at FROM dashboards WHERE owner = ? ORDER BY name`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Dashboard
	for rows.Next() {
		var d model.Dashboard
		var created int64
		if err := rows.Scan(&d.ID, &d.Name, &d.Spec, &created); err != nil {
			return nil, err
		}
		d.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteDashboard removes one of an owner's dashboards by id.
func (s *Store) DeleteDashboard(ctx context.Context, owner string, id int64) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM dashboards WHERE owner = ? AND id = ?`, owner, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
