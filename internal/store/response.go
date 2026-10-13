package store

import (
	"context"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// ---- playbooks (auto-response) ----

func (s *Store) CreatePlaybook(ctx context.Context, p model.Playbook) (model.Playbook, error) {
	id, err := randomID(6)
	if err != nil {
		return p, err
	}
	p.ID = id
	p.CreatedAt = time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `
INSERT INTO playbooks (id, org_id, name, enabled, on_severity, on_rule, action, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.OrgID, p.Name, b2i(p.Enabled), p.OnSeverity, p.OnRule, p.Action, p.CreatedAt.Unix())
	return p, err
}

func (s *Store) Playbooks(ctx context.Context, orgID string) ([]model.Playbook, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, org_id, name, enabled, on_severity, on_rule, action, created_at
FROM playbooks WHERE org_id = ? ORDER BY created_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Playbook
	for rows.Next() {
		var p model.Playbook
		var enabled int
		var created int64
		if err := rows.Scan(&p.ID, &p.OrgID, &p.Name, &enabled, &p.OnSeverity, &p.OnRule, &p.Action, &created); err != nil {
			return nil, err
		}
		p.Enabled = enabled != 0
		p.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) SetPlaybookEnabled(ctx context.Context, orgID, id string, enabled bool) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE playbooks SET enabled = ? WHERE id = ? AND org_id = ?`, b2i(enabled), id, orgID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *Store) DeletePlaybook(ctx context.Context, orgID, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM playbooks WHERE id = ? AND org_id = ?`, id, orgID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// LatestContainment returns the most recent isolate/unisolate action type for an
// endpoint ("isolate", "unisolate", or "") — so auto-response doesn't re-isolate
// an already-contained host.
func (s *Store) LatestContainment(ctx context.Context, endpointID string) (string, error) {
	var typ string
	err := s.db.QueryRowContext(ctx, `
SELECT type FROM actions WHERE endpoint_id = ? AND type IN ('isolate','unisolate')
ORDER BY id DESC LIMIT 1`, endpointID).Scan(&typ)
	if err != nil {
		return "", nil
	}
	return typ, nil
}

// ---- silences ----

func (s *Store) CreateSilence(ctx context.Context, sl model.Silence) (model.Silence, error) {
	id, err := randomID(6)
	if err != nil {
		return sl, err
	}
	sl.ID = id
	sl.CreatedAt = time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `
INSERT INTO silences (id, org_id, name, match_rule, match_endpoint, until, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sl.ID, sl.OrgID, sl.Name, sl.MatchRule, sl.MatchEndpoint, sl.Until.Unix(), sl.CreatedAt.Unix())
	return sl, err
}

func (s *Store) Silences(ctx context.Context, orgID string) ([]model.Silence, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, org_id, name, match_rule, match_endpoint, until, created_at
FROM silences WHERE org_id = ? ORDER BY until DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Silence
	for rows.Next() {
		var sl model.Silence
		var until, created int64
		if err := rows.Scan(&sl.ID, &sl.OrgID, &sl.Name, &sl.MatchRule, &sl.MatchEndpoint, &until, &created); err != nil {
			return nil, err
		}
		sl.Until = time.Unix(until, 0).UTC()
		sl.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, sl)
	}
	return out, rows.Err()
}

// ActiveSilences returns an org's silences that have not yet expired.
func (s *Store) ActiveSilences(ctx context.Context, orgID string) ([]model.Silence, error) {
	all, err := s.Silences(ctx, orgID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := all[:0]
	for _, sl := range all {
		if sl.Until.After(now) {
			out = append(out, sl)
		}
	}
	return out, nil
}

func (s *Store) DeleteSilence(ctx context.Context, orgID, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM silences WHERE id = ? AND org_id = ?`, id, orgID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
