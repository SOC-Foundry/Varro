package store

import (
	"context"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// AppendAudit records one administrative action. orgID "" marks an
// instance-level action (e.g. creating an org) visible only to instance
// admins.
func (s *Store) AppendAudit(ctx context.Context, actor, action, orgID, target string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_log (ts, actor, action, org_id, target) VALUES (?, ?, ?, ?, ?)`,
		time.Now().Unix(), actor, action, orgID, target)
	return err
}

// Audit returns audit entries newest-first. orgIDs nil = all orgs (instance
// admin); otherwise only entries scoped to those orgs.
func (s *Store) Audit(ctx context.Context, orgIDs []string, limit int) ([]model.AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	filter, args := orgFilter("org_id", orgIDs)
	q := `SELECT id, ts, actor, action, org_id, target FROM audit_log WHERE 1=1` + filter +
		` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.OrgID, &e.Target); err != nil {
			return nil, err
		}
		e.Timestamp = time.Unix(ts, 0).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneAudit trims audit entries older than the retention window.
func (s *Store) PruneAudit(ctx context.Context, retention time.Duration) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM audit_log WHERE ts < ?`, time.Now().Add(-retention).Unix())
	return err
}
