package store

import (
	"context"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// SetReportSchedule upserts an org's digest configuration.
func (s *Store) SetReportSchedule(ctx context.Context, sc model.ReportSchedule) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO report_schedules (org_id, enabled, cadence, recipients, last_sent)
VALUES (?, ?, ?, ?, 0)
ON CONFLICT(org_id) DO UPDATE SET enabled = excluded.enabled, cadence = excluded.cadence, recipients = excluded.recipients`,
		sc.OrgID, b2i(sc.Enabled), sc.Cadence, strings.Join(sc.Recipients, ","))
	return err
}

// ReportSchedule returns an org's digest config (zero value if none).
func (s *Store) ReportSchedule(ctx context.Context, orgID string) (model.ReportSchedule, error) {
	var sc model.ReportSchedule
	sc.OrgID = orgID
	sc.Cadence = "weekly"
	var enabled int
	var recipients string
	var lastSent int64
	err := s.db.QueryRowContext(ctx,
		`SELECT enabled, cadence, recipients, last_sent FROM report_schedules WHERE org_id = ?`, orgID).
		Scan(&enabled, &sc.Cadence, &recipients, &lastSent)
	if err != nil {
		return sc, nil // no row → disabled default
	}
	sc.Enabled = enabled != 0
	sc.Recipients = splitList(recipients)
	if lastSent > 0 {
		sc.LastSent = time.Unix(lastSent, 0).UTC()
	}
	return sc, nil
}

// DueReportSchedules returns enabled schedules whose cadence interval has elapsed
// since the last send (leader scheduler's work list).
func (s *Store) DueReportSchedules(ctx context.Context) ([]model.ReportSchedule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT org_id, cadence, recipients, last_sent FROM report_schedules WHERE enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now()
	var out []model.ReportSchedule
	for rows.Next() {
		var sc model.ReportSchedule
		var recipients string
		var lastSent int64
		if err := rows.Scan(&sc.OrgID, &sc.Cadence, &recipients, &lastSent); err != nil {
			return nil, err
		}
		sc.Enabled = true
		sc.Recipients = splitList(recipients)
		sc.LastSent = time.Unix(lastSent, 0).UTC()
		if len(sc.Recipients) == 0 {
			continue
		}
		if now.Sub(sc.LastSent) >= cadenceInterval(sc.Cadence) {
			out = append(out, sc)
		}
	}
	return out, rows.Err()
}

// MarkReportSent records a digest send time.
func (s *Store) MarkReportSent(ctx context.Context, orgID string, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE report_schedules SET last_sent = ? WHERE org_id = ?`, at.Unix(), orgID)
	return err
}

// IncidentCounts returns an org's open and open-CRITICAL incident counts for the
// digest.
func (s *Store) IncidentCounts(ctx context.Context, orgID string) (open, critical int, err error) {
	err = s.db.QueryRowContext(ctx, `
SELECT
  CAST(COUNT(*) AS BIGINT),
  CAST(COALESCE(SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) AS BIGINT)
FROM incidents WHERE org_id = ? AND status != 'resolved'`, orgID).Scan(&open, &critical)
	return open, critical, err
}

func cadenceInterval(c string) time.Duration {
	if c == "daily" {
		return 24 * time.Hour
	}
	return 7 * 24 * time.Hour
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
