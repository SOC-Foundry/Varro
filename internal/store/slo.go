package store

import (
	"context"

	"github.com/soc-foundry/varro/internal/model"
)

// UpsertSLO inserts or updates a service's SLO definition for an org.
func (s *Store) UpsertSLO(ctx context.Context, slo model.SLO) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO slos (org_id, service, target, window_minutes)
VALUES (?, ?, ?, ?)
ON CONFLICT (org_id, service) DO UPDATE SET target = excluded.target, window_minutes = excluded.window_minutes`,
		slo.OrgID, slo.Service, slo.Target, slo.WindowMinutes)
	return err
}

// ListSLOs returns an org's SLO definitions.
func (s *Store) ListSLOs(ctx context.Context, orgID string) ([]model.SLO, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT service, target, window_minutes FROM slos WHERE org_id = ? ORDER BY service`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SLO
	for rows.Next() {
		slo := model.SLO{OrgID: orgID}
		if err := rows.Scan(&slo.Service, &slo.Target, &slo.WindowMinutes); err != nil {
			return nil, err
		}
		out = append(out, slo)
	}
	return out, rows.Err()
}

// DeleteSLO removes a service's SLO from an org.
func (s *Store) DeleteSLO(ctx context.Context, orgID, service string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM slos WHERE org_id = ? AND service = ?`, orgID, service)
	return err
}

// SLOsForOrgs returns SLO definitions across the given orgs (nil = all), for the
// read path and the breach-check loop.
func (s *Store) SLOsForOrgs(ctx context.Context, orgIDs []string) ([]model.SLO, error) {
	filter, args := orgFilter("org_id", orgIDs)
	rows, err := s.db.QueryContext(ctx,
		`SELECT org_id, service, target, window_minutes FROM slos WHERE 1=1`+filter+` ORDER BY org_id, service`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SLO
	for rows.Next() {
		var slo model.SLO
		if err := rows.Scan(&slo.OrgID, &slo.Service, &slo.Target, &slo.WindowMinutes); err != nil {
			return nil, err
		}
		out = append(out, slo)
	}
	return out, rows.Err()
}
