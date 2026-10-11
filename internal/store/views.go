package store

import (
	"context"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// SaveView stores (or replaces, by owner+name) a saved metric-explorer view.
func (s *Store) SaveView(ctx context.Context, owner, orgID, name, spec string) error {
	// Replace any existing view with the same owner+name so "save" is idempotent.
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM saved_views WHERE owner = ? AND name = ?`, owner, name); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO saved_views (owner, org_id, name, spec, created_at) VALUES (?, ?, ?, ?, ?)`,
		owner, orgID, name, spec, time.Now().Unix())
	return err
}

// ListViews returns an owner's saved views, newest first.
func (s *Store) ListViews(ctx context.Context, owner string) ([]model.SavedView, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, spec, created_at FROM saved_views WHERE owner = ? ORDER BY name`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SavedView
	for rows.Next() {
		var v model.SavedView
		var created int64
		if err := rows.Scan(&v.ID, &v.Name, &v.Spec, &created); err != nil {
			return nil, err
		}
		v.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, v)
	}
	return out, rows.Err()
}

// DeleteView removes one of an owner's saved views by id.
func (s *Store) DeleteView(ctx context.Context, owner string, id int64) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM saved_views WHERE owner = ? AND id = ?`, owner, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
