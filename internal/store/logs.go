package store

import (
	"context"
	"strings"

	"github.com/soc-foundry/varro/internal/model"
)

// InsertLogs stores a batch of log lines for one endpoint/org.
func (s *Store) InsertLogs(ctx context.Context, orgID, endpointID string, entries []model.LogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ins, err := tx.PrepareContext(ctx,
		`INSERT INTO logs (org_id, endpoint_id, ts, severity, source, message) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer ins.Close()
	for _, e := range entries {
		if e.Message == "" {
			continue
		}
		if _, err := ins.ExecContext(ctx, orgID, endpointID, e.TS, e.Severity, e.Source, e.Message); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LogQuery narrows a log search. Zero-value fields are ignored.
type LogQuery struct {
	OrgIDs     []string // nil = all orgs
	EndpointID string   // "" = all endpoints in scope
	Severity   string   // "" = all severities
	Text       string   // "" = no text filter; substring match on message
	Since      int64    // unix seconds; 0 = no lower bound
	Limit      int      // capped by the caller
}

// QueryLogs returns matching log lines newest-first, joined to the endpoint's
// hostname for display.
func (s *Store) QueryLogs(ctx context.Context, q LogQuery) ([]model.StoredLog, error) {
	var sb strings.Builder
	sb.WriteString(`
SELECT l.org_id, l.endpoint_id, COALESCE(e.hostname, ''), l.ts, l.severity, l.source, l.message
FROM logs l LEFT JOIN endpoints e ON e.id = l.endpoint_id
WHERE 1=1`)
	var args []any
	if filter, fargs := orgFilter("l.org_id", q.OrgIDs); filter != "" {
		sb.WriteString(filter)
		args = append(args, fargs...)
	}
	if q.EndpointID != "" {
		sb.WriteString(" AND l.endpoint_id = ?")
		args = append(args, q.EndpointID)
	}
	if q.Severity != "" {
		sb.WriteString(" AND l.severity = ?")
		args = append(args, q.Severity)
	}
	if q.Since > 0 {
		sb.WriteString(" AND l.ts >= ?")
		args = append(args, q.Since)
	}
	if q.Text != "" {
		sb.WriteString(" AND l.message LIKE ?")
		args = append(args, "%"+q.Text+"%")
	}
	sb.WriteString(" ORDER BY l.ts DESC, l.id DESC LIMIT ?")
	args = append(args, q.Limit)

	rows, err := s.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.StoredLog
	for rows.Next() {
		var l model.StoredLog
		if err := rows.Scan(&l.OrgID, &l.EndpointID, &l.Hostname, &l.TS, &l.Severity, &l.Source, &l.Message); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
