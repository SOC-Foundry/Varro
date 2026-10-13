package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// CreateSyntheticCheck stores a new uptime check and returns it with its
// generated ID.
func (s *Store) CreateSyntheticCheck(ctx context.Context, c model.SyntheticCheck) (model.SyntheticCheck, error) {
	id, err := randomID(6)
	if err != nil {
		return c, err
	}
	c.ID = id
	c.CreatedAt = time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `
INSERT INTO synthetic_checks (id, org_id, name, type, target, interval_s, expect_code, enabled, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.OrgID, c.Name, c.Type, c.Target, c.IntervalS, c.ExpectCode, b2i(c.Enabled), c.CreatedAt.Unix())
	return c, err
}

// DeleteSyntheticCheck removes a check (and its results) if it is within scope.
// A nil scope (instance admin / master) may delete any check.
func (s *Store) DeleteSyntheticCheck(ctx context.Context, scope []string, id string) (bool, error) {
	filter, args := orgFilter("org_id", scope)
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM synthetic_checks WHERE id = ?`+filter, append([]any{id}, args...)...)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	// Best-effort cleanup of the check's recorded results.
	_, _ = s.db.ExecContext(ctx, `DELETE FROM probe_results WHERE check_id = ?`, id)
	return true, nil
}

// SyntheticChecks returns the checks within scope (nil = all orgs).
func (s *Store) SyntheticChecks(ctx context.Context, scope []string) ([]model.SyntheticCheck, error) {
	filter, args := orgFilter("org_id", scope)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, org_id, name, type, target, interval_s, expect_code, enabled, created_at
FROM synthetic_checks WHERE 1=1`+filter+` ORDER BY name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanChecks(rows)
}

// EnabledSyntheticChecks returns every enabled check across all orgs — the
// prober's work list (runs leader-only).
func (s *Store) EnabledSyntheticChecks(ctx context.Context) ([]model.SyntheticCheck, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, org_id, name, type, target, interval_s, expect_code, enabled, created_at
FROM synthetic_checks WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanChecks(rows)
}

func scanChecks(rows *sql.Rows) ([]model.SyntheticCheck, error) {
	var out []model.SyntheticCheck
	for rows.Next() {
		var c model.SyntheticCheck
		var enabled int
		var created int64
		if err := rows.Scan(&c.ID, &c.OrgID, &c.Name, &c.Type, &c.Target,
			&c.IntervalS, &c.ExpectCode, &enabled, &created); err != nil {
			return nil, err
		}
		c.Enabled = enabled != 0
		c.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

// InsertProbeResult records one probe outcome.
func (s *Store) InsertProbeResult(ctx context.Context, r model.ProbeResult, orgID string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO probe_results (check_id, org_id, ts, ok, latency_ms, code, error)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.CheckID, orgID, r.TS, b2i(r.OK), r.LatencyMs, r.Code, r.Error)
	return err
}

// ProbeResults returns a check's recent results (newest first), scope-guarded.
func (s *Store) ProbeResults(ctx context.Context, scope []string, checkID string, since int64, limit int) ([]model.ProbeResult, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	filter, args := orgFilter("org_id", scope)
	q := `SELECT check_id, ts, ok, latency_ms, code, error FROM probe_results
WHERE check_id = ? AND ts >= ?` + filter + ` ORDER BY ts DESC LIMIT ?`
	args = append([]any{checkID, since}, args...)
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ProbeResult
	for rows.Next() {
		var r model.ProbeResult
		var ok int
		if err := rows.Scan(&r.CheckID, &r.TS, &ok, &r.LatencyMs, &r.Code, &r.Error); err != nil {
			return nil, err
		}
		r.OK = ok != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// SyntheticStatuses returns each in-scope check with its latest result and 24h
// uptime, for the dashboard list.
func (s *Store) SyntheticStatuses(ctx context.Context, scope []string) ([]model.SyntheticStatus, error) {
	checks, err := s.SyntheticChecks(ctx, scope)
	if err != nil {
		return nil, err
	}
	since := time.Now().Add(-24 * time.Hour).Unix()
	out := make([]model.SyntheticStatus, 0, len(checks))
	for _, c := range checks {
		st := model.SyntheticStatus{SyntheticCheck: c}
		// Latest result.
		var ok int
		var lat float64
		var code int
		var errStr string
		var ts int64
		err := s.db.QueryRowContext(ctx, `
SELECT ok, latency_ms, code, error, ts FROM probe_results
WHERE check_id = ? ORDER BY ts DESC LIMIT 1`, c.ID).Scan(&ok, &lat, &code, &errStr, &ts)
		if err == nil {
			st.Up = ok != 0
			st.LastLatency = lat
			st.LastCode = code
			st.LastError = errStr
			st.LastTS = ts
		}
		// 24h uptime. CAST keeps SUM's type as a plain integer on Postgres
		// (where SUM(bigint) is otherwise numeric and won't scan into int64).
		var total, good int64
		_ = s.db.QueryRowContext(ctx, `
SELECT COUNT(*), CAST(COALESCE(SUM(ok), 0) AS BIGINT) FROM probe_results
WHERE check_id = ? AND ts >= ?`, c.ID, since).Scan(&total, &good)
		st.Samples24h = int(total)
		if total > 0 {
			st.UptimePct = 100 * float64(good) / float64(total)
		}
		out = append(out, st)
	}
	return out, nil
}

// OrgIsInfrastructure reports whether an org is flagged as infrastructure
// (used to relax the synthetic-probe SSRF policy for operator-owned infra orgs).
func (s *Store) OrgIsInfrastructure(ctx context.Context, orgID string) (bool, error) {
	var infra int
	err := s.db.QueryRowContext(ctx,
		`SELECT infrastructure FROM orgs WHERE id = ?`, orgID).Scan(&infra)
	if err != nil {
		return false, err
	}
	return infra != 0, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
