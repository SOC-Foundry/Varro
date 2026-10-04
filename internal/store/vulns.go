package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// ReplaceEndpointVulns swaps an endpoint's finding set for the scan's result
// and returns the findings that were not present before (for events).
func (s *Store) ReplaceEndpointVulns(ctx context.Context, endpointID string, found []model.Vulnerability, inventoryTS int64) ([]model.Vulnerability, error) {
	prev := map[string]bool{}
	rows, err := s.db.QueryContext(ctx,
		`SELECT pkg, vuln_id FROM vulns WHERE endpoint_id = ?`, endpointID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var pkg, id string
		if err := rows.Scan(&pkg, &id); err != nil {
			rows.Close()
			return nil, err
		}
		prev[pkg+"|"+id] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM vulns WHERE endpoint_id = ?`, endpointID); err != nil {
		return nil, err
	}
	ins, err := tx.PrepareContext(ctx,
		`INSERT OR IGNORE INTO vulns (endpoint_id, pkg, version, vuln_id) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return nil, err
	}
	defer ins.Close()
	var fresh []model.Vulnerability
	for _, v := range found {
		if _, err := ins.ExecContext(ctx, endpointID, v.Package, v.Version, v.ID); err != nil {
			return nil, err
		}
		if !prev[v.Package+"|"+v.ID] {
			fresh = append(fresh, v)
		}
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO vuln_scans (endpoint_id, scanned_at, inventory_ts) VALUES (?, ?, ?)
ON CONFLICT(endpoint_id) DO UPDATE SET scanned_at=excluded.scanned_at, inventory_ts=excluded.inventory_ts`,
		endpointID, time.Now().Unix(), inventoryTS); err != nil {
		return nil, err
	}
	return fresh, tx.Commit()
}

// VulnScanState returns when the endpoint was last scanned and which
// inventory timestamp that scan covered (zeros when never scanned).
func (s *Store) VulnScanState(ctx context.Context, endpointID string) (scannedAt, inventoryTS int64, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT scanned_at, inventory_ts FROM vuln_scans WHERE endpoint_id = ?`, endpointID).
		Scan(&scannedAt, &inventoryTS)
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	return scannedAt, inventoryTS, err
}

// EndpointVulns lists an endpoint's findings joined with cached details.
func (s *Store) EndpointVulns(ctx context.Context, endpointID string) ([]model.Vulnerability, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT v.pkg, v.version, v.vuln_id, COALESCE(d.severity, ''), COALESCE(d.summary, '')
FROM vulns v LEFT JOIN vuln_details d ON d.id = v.vuln_id
WHERE v.endpoint_id = ? ORDER BY v.pkg, v.vuln_id`, endpointID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Vulnerability
	for rows.Next() {
		var v model.Vulnerability
		if err := rows.Scan(&v.Package, &v.Version, &v.ID, &v.Severity, &v.Summary); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// VulnCount returns how many findings an endpoint currently has.
func (s *Store) VulnCount(ctx context.Context, endpointID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vulns WHERE endpoint_id = ?`, endpointID).Scan(&n)
	return n, err
}

// UnknownVulnIDs returns referenced vuln IDs with no cached details yet.
func (s *Store) UnknownVulnIDs(ctx context.Context, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT v.vuln_id FROM vulns v
LEFT JOIN vuln_details d ON d.id = v.vuln_id
WHERE d.id IS NULL LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SetVulnDetail caches severity/summary for a vuln ID.
func (s *Store) SetVulnDetail(ctx context.Context, id, severity, summary string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO vuln_details (id, severity, summary, fetched_at) VALUES (?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET severity=excluded.severity, summary=excluded.summary, fetched_at=excluded.fetched_at`,
		id, severity, summary, time.Now().Unix())
	return err
}
