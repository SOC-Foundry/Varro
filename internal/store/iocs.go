package store

import (
	"context"

	"github.com/soc-foundry/varro/internal/model"
)

// UpsertIOCs inserts or updates a batch of indicators for one org, returning how
// many rows were written. Idempotent: re-ingesting a feed refreshes source/label
// without duplicating. Blank types/values are skipped.
func (s *Store) UpsertIOCs(ctx context.Context, orgID string, iocs []model.IOC) (int, error) {
	if len(iocs) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	ins, err := tx.PrepareContext(ctx, `
INSERT INTO iocs (org_id, ioc_type, value, source, label, added_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (org_id, ioc_type, value) DO UPDATE SET source = excluded.source, label = excluded.label`)
	if err != nil {
		return 0, err
	}
	defer ins.Close()
	n := 0
	for _, ioc := range iocs {
		if ioc.Type == "" || ioc.Value == "" {
			continue
		}
		src := ioc.Source
		if src == "" {
			src = "manual"
		}
		if _, err := ins.ExecContext(ctx, orgID, ioc.Type, ioc.Value, src, ioc.Label, ioc.AddedAt); err != nil {
			return 0, err
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// ListIOCs returns an org's indicators, newest first, optionally filtered by type
// and a value substring, capped at limit.
func (s *Store) ListIOCs(ctx context.Context, orgID, typeFilter, q string, limit int) ([]model.IOC, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	query := `SELECT ioc_type, value, source, label, added_at FROM iocs WHERE org_id = ?`
	args := []any{orgID}
	if typeFilter != "" {
		query += ` AND ioc_type = ?`
		args = append(args, typeFilter)
	}
	if q != "" {
		query += ` AND value LIKE ?`
		args = append(args, "%"+q+"%")
	}
	query += ` ORDER BY added_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.IOC
	for rows.Next() {
		var ioc model.IOC
		if err := rows.Scan(&ioc.Type, &ioc.Value, &ioc.Source, &ioc.Label, &ioc.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, ioc)
	}
	return out, rows.Err()
}

// CountIOCs tallies an org's indicators by type.
func (s *Store) CountIOCs(ctx context.Context, orgID string) (model.IOCCounts, error) {
	var c model.IOCCounts
	rows, err := s.db.QueryContext(ctx,
		`SELECT ioc_type, COUNT(*) FROM iocs WHERE org_id = ? GROUP BY ioc_type`, orgID)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return c, err
		}
		switch t {
		case model.IOCTypeIP:
			c.IP = n
		case model.IOCTypeDomain:
			c.Domain = n
		case model.IOCTypeHash:
			c.Hash = n
		}
	}
	return c, rows.Err()
}

// DeleteIOC removes one indicator from an org.
func (s *Store) DeleteIOC(ctx context.Context, orgID, iocType, value string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM iocs WHERE org_id = ? AND ioc_type = ? AND value = ?`, orgID, iocType, value)
	return err
}

// AllIOCs returns every org's indicators, for building the in-memory matcher.
// Bounded to avoid unbounded memory on a very large corpus.
func (s *Store) AllIOCs(ctx context.Context) ([]model.IOC, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT org_id, ioc_type, value FROM iocs LIMIT 500000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.IOC
	for rows.Next() {
		var ioc model.IOC
		if err := rows.Scan(&ioc.OrgID, &ioc.Type, &ioc.Value); err != nil {
			return nil, err
		}
		out = append(out, ioc)
	}
	return out, rows.Err()
}

// AddSTIXFeed persists a STIX/TAXII feed configuration for an org, assigning an ID.
func (s *Store) AddSTIXFeed(ctx context.Context, f model.STIXFeed) (model.STIXFeed, error) {
	id, err := randomID(6)
	if err != nil {
		return f, err
	}
	f.ID = id
	_, err = s.db.ExecContext(ctx, `
INSERT INTO stix_feeds (id, org_id, url, kind, enabled, added_at)
VALUES (?, ?, ?, ?, ?, ?)`, f.ID, f.OrgID, f.URL, f.Kind, b2i(f.Enabled), f.AddedAt)
	return f, err
}

// ListSTIXFeeds returns an org's configured feeds, newest first.
func (s *Store) ListSTIXFeeds(ctx context.Context, orgID string) ([]model.STIXFeed, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, url, kind, enabled, added_at, last_run, last_count, last_status
FROM stix_feeds WHERE org_id = ? ORDER BY added_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.STIXFeed
	for rows.Next() {
		var f model.STIXFeed
		var en int
		if err := rows.Scan(&f.ID, &f.URL, &f.Kind, &en, &f.AddedAt, &f.LastRun, &f.LastCount, &f.LastStatus); err != nil {
			return nil, err
		}
		f.Enabled = en != 0
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetSTIXFeed loads one feed scoped to its org (nil if not found).
func (s *Store) GetSTIXFeed(ctx context.Context, orgID, id string) (*model.STIXFeed, error) {
	var f model.STIXFeed
	var en int
	err := s.db.QueryRowContext(ctx, `
SELECT id, org_id, url, kind, enabled, added_at, last_run, last_count, last_status
FROM stix_feeds WHERE org_id = ? AND id = ?`, orgID, id).
		Scan(&f.ID, &f.OrgID, &f.URL, &f.Kind, &en, &f.AddedAt, &f.LastRun, &f.LastCount, &f.LastStatus)
	if err != nil {
		return nil, err
	}
	f.Enabled = en != 0
	return &f, nil
}

// DeleteSTIXFeed removes a feed (its already-ingested IOCs remain).
func (s *Store) DeleteSTIXFeed(ctx context.Context, orgID, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM stix_feeds WHERE org_id = ? AND id = ?`, orgID, id)
	return err
}

// AllEnabledSTIXFeeds returns every enabled feed across orgs, for the poll loop.
func (s *Store) AllEnabledSTIXFeeds(ctx context.Context) ([]model.STIXFeed, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, org_id, url, kind, enabled, added_at, last_run, last_count, last_status
FROM stix_feeds WHERE enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.STIXFeed
	for rows.Next() {
		var f model.STIXFeed
		var en int
		if err := rows.Scan(&f.ID, &f.OrgID, &f.URL, &f.Kind, &en, &f.AddedAt, &f.LastRun, &f.LastCount, &f.LastStatus); err != nil {
			return nil, err
		}
		f.Enabled = en != 0
		out = append(out, f)
	}
	return out, rows.Err()
}

// UpdateSTIXFeedStatus records the outcome of a feed poll.
func (s *Store) UpdateSTIXFeedStatus(ctx context.Context, id string, runAt int64, count int, status string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE stix_feeds SET last_run = ?, last_count = ?, last_status = ? WHERE id = ?`,
		runAt, count, status, id)
	return err
}
