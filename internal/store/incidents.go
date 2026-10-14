package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// incidentWindow groups signals for the same endpoint into one incident while it
// stays active; a signal after that (or after resolution) starts a new incident.
const incidentWindow = 2 * time.Hour

var incSevRank = map[string]int{"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

// SignalResult reports how AttachSignal affected an incident, so the caller can
// notify on a newly-opened incident or an escalation to CRITICAL.
type SignalResult struct {
	ID        int64
	Created   bool // a new incident was opened
	Escalated bool // an existing incident's severity rose to CRITICAL
}

// AttachSignal correlates an alert/detection into an incident: it appends to the
// endpoint's active incident (if one was updated within incidentWindow) or opens
// a new one, raising severity to the max seen.
func (s *Store) AttachSignal(ctx context.Context, orgID, endpointID, hostname, kind, severity, title, message string) (SignalResult, error) {
	if severity == "" {
		severity = "MEDIUM"
	}
	now := time.Now()
	cut := now.Add(-incidentWindow).Unix()
	var res SignalResult

	var id int64
	var curSev string
	err := s.db.QueryRowContext(ctx, `
SELECT id, severity FROM incidents
WHERE org_id = ? AND endpoint_id = ? AND status != 'resolved' AND updated_at >= ?
ORDER BY id DESC LIMIT 1`, orgID, endpointID, cut).Scan(&id, &curSev)
	if err == sql.ErrNoRows {
		id = 0
	} else if err != nil {
		return res, err
	}

	if id == 0 {
		id, err = s.db.insertReturningID(ctx, `
INSERT INTO incidents (org_id, endpoint_id, hostname, title, status, severity, created_at, updated_at)
VALUES (?, ?, ?, ?, 'open', ?, ?, ?)`, orgID, endpointID, hostname, title, severity, now.Unix(), now.Unix())
		if err != nil {
			return res, err
		}
		res.Created = true
	} else {
		sev := curSev
		if incSevRank[severity] > incSevRank[curSev] {
			sev = severity
		}
		if sev == "CRITICAL" && curSev != "CRITICAL" {
			res.Escalated = true
		}
		if _, err := s.db.ExecContext(ctx,
			`UPDATE incidents SET updated_at = ?, severity = ? WHERE id = ?`, now.Unix(), sev, id); err != nil {
			return res, err
		}
	}
	res.ID = id
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO incident_items (incident_id, ts, kind, actor, message) VALUES (?, ?, ?, '', ?)`,
		id, now.Unix(), kind, message)
	return res, err
}

// IncidentOrg returns the org an incident belongs to (for scope checks), or "".
func (s *Store) IncidentOrg(ctx context.Context, id int64) (string, error) {
	var org string
	err := s.db.QueryRowContext(ctx, `SELECT org_id FROM incidents WHERE id = ?`, id).Scan(&org)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return org, err
}

// Incidents lists incidents in scope, newest-updated first.
func (s *Store) Incidents(ctx context.Context, orgIDs []string, status string, limit int) ([]model.Incident, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	filter, args := orgFilter("org_id", orgIDs)
	q := `
SELECT id, org_id, endpoint_id, hostname, title, status, severity, assignee, created_at, updated_at, resolved_at,
       (SELECT COUNT(*) FROM incident_items WHERE incident_id = incidents.id)
FROM incidents WHERE 1=1` + filter
	if status != "" {
		q += ` AND status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY updated_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Incident
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inc)
	}
	return out, rows.Err()
}

// IncidentDetail returns one incident with its full timeline.
func (s *Store) IncidentDetail(ctx context.Context, id int64) (*model.Incident, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, org_id, endpoint_id, hostname, title, status, severity, assignee, created_at, updated_at, resolved_at,
       (SELECT COUNT(*) FROM incident_items WHERE incident_id = incidents.id)
FROM incidents WHERE id = ?`, id)
	inc, err := scanIncident(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, kind, actor, message FROM incident_items WHERE incident_id = ? ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var it model.IncidentItem
		var ts int64
		if err := rows.Scan(&it.ID, &ts, &it.Kind, &it.Actor, &it.Message); err != nil {
			return nil, err
		}
		it.Timestamp = time.Unix(ts, 0).UTC()
		inc.Items = append(inc.Items, it)
	}
	return &inc, rows.Err()
}

type scanner interface{ Scan(...any) error }

func scanIncident(sc scanner) (model.Incident, error) {
	var inc model.Incident
	var created, updated int64
	var resolved sql.NullInt64
	if err := sc.Scan(&inc.ID, &inc.OrgID, &inc.EndpointID, &inc.Hostname, &inc.Title, &inc.Status,
		&inc.Severity, &inc.Assignee, &created, &updated, &resolved, &inc.ItemCount); err != nil {
		return inc, err
	}
	inc.CreatedAt = time.Unix(created, 0).UTC()
	inc.UpdatedAt = time.Unix(updated, 0).UTC()
	if resolved.Valid {
		t := time.Unix(resolved.Int64, 0).UTC()
		inc.ResolvedAt = &t
	}
	return inc, nil
}

// SetIncidentStatus updates status (+resolved_at) and records a timeline entry.
func (s *Store) SetIncidentStatus(ctx context.Context, id int64, status, actor string) error {
	now := time.Now().Unix()
	var err error
	if status == model.IncidentResolved {
		_, err = s.db.ExecContext(ctx,
			`UPDATE incidents SET status = ?, updated_at = ?, resolved_at = ? WHERE id = ?`, status, now, now, id)
	} else {
		_, err = s.db.ExecContext(ctx,
			`UPDATE incidents SET status = ?, updated_at = ?, resolved_at = NULL WHERE id = ?`, status, now, id)
	}
	if err != nil {
		return err
	}
	return s.addIncidentItem(ctx, id, "status", actor, "status → "+status)
}

// AssignIncident sets (or clears) the assignee and records it.
func (s *Store) AssignIncident(ctx context.Context, id int64, assignee, actor string) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE incidents SET assignee = ?, updated_at = ? WHERE id = ?`, assignee, time.Now().Unix(), id); err != nil {
		return err
	}
	msg := "assigned to " + assignee
	if assignee == "" {
		msg = "unassigned"
	}
	return s.addIncidentItem(ctx, id, "status", actor, msg)
}

// AddIncidentNote appends an operator note.
func (s *Store) AddIncidentNote(ctx context.Context, id int64, actor, note string) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE incidents SET updated_at = ? WHERE id = ?`, time.Now().Unix(), id); err != nil {
		return err
	}
	return s.addIncidentItem(ctx, id, "note", actor, note)
}

func (s *Store) addIncidentItem(ctx context.Context, id int64, kind, actor, message string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO incident_items (incident_id, ts, kind, actor, message) VALUES (?, ?, ?, ?, ?)`,
		id, time.Now().Unix(), kind, actor, message)
	return err
}
