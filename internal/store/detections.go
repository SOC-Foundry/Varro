package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// CreateDetectionRule stores a custom/Sigma detection rule.
func (s *Store) CreateDetectionRule(ctx context.Context, r model.DetectionRule) (model.DetectionRule, error) {
	id, err := randomID(6)
	if err != nil {
		return r, err
	}
	r.ID = id
	r.CreatedAt = time.Now().UTC()
	conds, _ := json.Marshal(r.Conditions)
	_, err = s.db.ExecContext(ctx, `
INSERT INTO detection_rules (id, org_id, name, enabled, severity, mitre, stream, conditions, source, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.OrgID, r.Name, b2i(r.Enabled), r.Severity, r.MITRE, r.Stream, string(conds), r.Source, r.CreatedAt.Unix())
	return r, err
}

// DetectionRules returns an org's custom rules.
func (s *Store) DetectionRules(ctx context.Context, orgID string) ([]model.DetectionRule, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, org_id, name, enabled, severity, mitre, stream, conditions, source, created_at
FROM detection_rules WHERE org_id = ? ORDER BY created_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.DetectionRule
	for rows.Next() {
		var r model.DetectionRule
		var enabled int
		var conds string
		var created int64
		if err := rows.Scan(&r.ID, &r.OrgID, &r.Name, &enabled, &r.Severity, &r.MITRE, &r.Stream, &conds, &r.Source, &created); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		json.Unmarshal([]byte(conds), &r.Conditions)
		r.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteDetectionRule removes a custom rule within an org.
func (s *Store) DeleteDetectionRule(ctx context.Context, orgID, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM detection_rules WHERE id = ? AND org_id = ?`, id, orgID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// SetDetectionRuleEnabled toggles a custom rule.
func (s *Store) SetDetectionRuleEnabled(ctx context.Context, orgID, id string, enabled bool) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE detection_rules SET enabled = ? WHERE id = ? AND org_id = ?`, b2i(enabled), id, orgID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// DetectionSettings returns an org's built-in rule overrides, keyed by rule name.
func (s *Store) DetectionSettings(ctx context.Context, orgID string) (map[string]model.DetectionSetting, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT rule_name, enabled, severity FROM detection_settings WHERE org_id = ?`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]model.DetectionSetting{}
	for rows.Next() {
		var st model.DetectionSetting
		var enabled int
		if err := rows.Scan(&st.RuleName, &enabled, &st.Severity); err != nil {
			return nil, err
		}
		st.Enabled = enabled != 0
		out[st.RuleName] = st
	}
	return out, rows.Err()
}

// SetDetectionSetting upserts a built-in rule override for an org.
func (s *Store) SetDetectionSetting(ctx context.Context, orgID string, st model.DetectionSetting) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO detection_settings (org_id, rule_name, enabled, severity) VALUES (?, ?, ?, ?)
ON CONFLICT(org_id, rule_name) DO UPDATE SET enabled = excluded.enabled, severity = excluded.severity`,
		orgID, st.RuleName, b2i(st.Enabled), st.Severity)
	return err
}
