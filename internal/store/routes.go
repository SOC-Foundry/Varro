package store

import (
	"context"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// CreateNotifyRoute stores a new per-org notification route.
func (s *Store) CreateNotifyRoute(ctx context.Context, r model.NotifyRoute) (model.NotifyRoute, error) {
	id, err := randomID(6)
	if err != nil {
		return r, err
	}
	r.ID = id
	r.CreatedAt = time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `
INSERT INTO notify_routes (id, org_id, type, target, min_severity, enabled, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.OrgID, r.Type, r.Target, r.MinSeverity, b2i(r.Enabled), r.CreatedAt.Unix())
	return r, err
}

// NotifyRoutes returns an org's routes.
func (s *Store) NotifyRoutes(ctx context.Context, orgID string) ([]model.NotifyRoute, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, org_id, type, target, min_severity, enabled, created_at
FROM notify_routes WHERE org_id = ? ORDER BY created_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.NotifyRoute
	for rows.Next() {
		var r model.NotifyRoute
		var enabled int
		var created int64
		if err := rows.Scan(&r.ID, &r.OrgID, &r.Type, &r.Target, &r.MinSeverity, &enabled, &created); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		r.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// EnabledNotifyRoutes returns an org's enabled routes (the dispatch path).
func (s *Store) EnabledNotifyRoutes(ctx context.Context, orgID string) ([]model.NotifyRoute, error) {
	all, err := s.NotifyRoutes(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, r := range all {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out, nil
}

// DeleteNotifyRoute removes a route if it belongs to orgID.
func (s *Store) DeleteNotifyRoute(ctx context.Context, orgID, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM notify_routes WHERE id = ? AND org_id = ?`, id, orgID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
