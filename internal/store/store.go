// Package store persists telemetry in SQLite (pure-Go driver, no cgo).
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/soc-foundry/varro/internal/model"
)

// onlineWindow is how recently an endpoint must have reported to be
// considered online.
const onlineWindow = 60 * time.Second

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	// The modernc driver serializes writes; a single connection avoids
	// SQLITE_BUSY churn under concurrent ingest.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS endpoints (
	id         TEXT PRIMARY KEY,
	hostname   TEXT NOT NULL,
	os         TEXT NOT NULL DEFAULT '',
	platform   TEXT NOT NULL DEFAULT '',
	arch       TEXT NOT NULL DEFAULT '',
	cores      INTEGER NOT NULL DEFAULT 0,
	mem_total  INTEGER NOT NULL DEFAULT 0,
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS samples (
	id          INTEGER PRIMARY KEY,
	endpoint_id TEXT NOT NULL REFERENCES endpoints(id),
	ts          INTEGER NOT NULL,
	cpu_pct     REAL NOT NULL,
	mem_pct     REAL NOT NULL,
	mem_used    INTEGER NOT NULL,
	rx_rate     REAL NOT NULL,
	tx_rate     REAL NOT NULL,
	disk_pct    REAL NOT NULL,
	payload     BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_endpoint_ts ON samples(endpoint_id, ts);
CREATE TABLE IF NOT EXISTS events (
	id          INTEGER PRIMARY KEY,
	endpoint_id TEXT NOT NULL,
	ts          INTEGER NOT NULL,
	type        TEXT NOT NULL,
	message     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_endpoint_ts ON events(endpoint_id, ts);
CREATE TABLE IF NOT EXISTS alerts (
	id          INTEGER PRIMARY KEY,
	rule        TEXT NOT NULL,
	endpoint_id TEXT NOT NULL,
	hostname    TEXT NOT NULL,
	state       TEXT NOT NULL,
	message     TEXT NOT NULL,
	value       REAL NOT NULL,
	started_at  INTEGER NOT NULL,
	resolved_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_open ON alerts(rule, endpoint_id) WHERE state = 'firing';
CREATE TABLE IF NOT EXISTS agent_tokens (
	agent_id   TEXT PRIMARY KEY,
	token_hash TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS orgs (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL UNIQUE,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS org_tokens (
	token_hash TEXT PRIMARY KEY,
	org_id     TEXT NOT NULL REFERENCES orgs(id),
	name       TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
	id         TEXT PRIMARY KEY,
	email      TEXT NOT NULL UNIQUE,
	name       TEXT NOT NULL DEFAULT '',
	google_sub TEXT NOT NULL DEFAULT '',
	is_admin   INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS org_members (
	org_id TEXT NOT NULL REFERENCES orgs(id),
	email  TEXT NOT NULL,
	role   TEXT NOT NULL DEFAULT 'member',
	PRIMARY KEY (org_id, email)
);
CREATE TABLE IF NOT EXISTS sessions (
	id_hash    TEXT PRIMARY KEY,
	user_id    TEXT NOT NULL REFERENCES users(id),
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS inventory (
	endpoint_id TEXT PRIMARY KEY,
	ts          INTEGER NOT NULL,
	kernel      TEXT NOT NULL DEFAULT '',
	manager     TEXT NOT NULL DEFAULT '',
	packages    BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS edges (
	org_id     TEXT NOT NULL,
	src_id     TEXT NOT NULL,
	dst_id     TEXT NOT NULL,
	process    TEXT NOT NULL,
	dst_port   INTEGER NOT NULL,
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	PRIMARY KEY (src_id, dst_id, process, dst_port)
);
CREATE INDEX IF NOT EXISTS idx_edges_org_seen ON edges(org_id, last_seen);
`)
	if err != nil {
		return err
	}
	// Additive column migrations for databases created before v0.2/v0.3; the
	// "duplicate column" error on re-run is expected and ignored.
	for _, stmt := range []string{
		`ALTER TABLE endpoints ADD COLUMN agent_version TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE samples ADD COLUMN swap_pct REAL NOT NULL DEFAULT 0`,
		`ALTER TABLE endpoints ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default'`,
		`ALTER TABLE agent_tokens ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default'`,
		`ALTER TABLE alerts ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default'`,
		`ALTER TABLE events ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default'`,
		`ALTER TABLE samples ADD COLUMN max_temp REAL NOT NULL DEFAULT 0`,
		`ALTER TABLE samples ADD COLUMN io_read_bps REAL NOT NULL DEFAULT 0`,
		`ALTER TABLE samples ADD COLUMN io_write_bps REAL NOT NULL DEFAULT 0`,
		`ALTER TABLE orgs ADD COLUMN auto_join_domain TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE orgs ADD COLUMN fim_paths TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE samples ADD COLUMN posture_fails INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE samples ADD COLUMN pending_updates INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := s.db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	// The default org always exists; legacy agents and master-token ingest
	// land here.
	_, err = s.db.Exec(`INSERT OR IGNORE INTO orgs (id, name, created_at) VALUES (?, 'Default', ?)`,
		model.DefaultOrg, time.Now().Unix())
	return err
}

// orgFilter builds "AND col IN (...)" for an org scope; nil means all orgs
// (no filtering).
func orgFilter(col string, orgIDs []string) (string, []any) {
	if orgIDs == nil {
		return "", nil
	}
	ph := make([]string, len(orgIDs))
	args := make([]any, len(orgIDs))
	for i, id := range orgIDs {
		ph[i] = "?"
		args[i] = id
	}
	return " AND " + col + " IN (" + strings.Join(ph, ",") + ")", args
}

// Insert stores a batch of snapshots under one org and upserts their
// endpoints.
func (s *Store) Insert(ctx context.Context, snaps []*model.Snapshot, orgID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	upsert, err := tx.PrepareContext(ctx, `
INSERT INTO endpoints (id, hostname, os, platform, arch, cores, mem_total, agent_version, org_id, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	hostname=excluded.hostname, os=excluded.os, platform=excluded.platform,
	arch=excluded.arch, cores=excluded.cores, mem_total=excluded.mem_total,
	agent_version=excluded.agent_version, org_id=excluded.org_id,
	last_seen=MAX(endpoints.last_seen, excluded.last_seen)`)
	if err != nil {
		return err
	}
	defer upsert.Close()

	insert, err := tx.PrepareContext(ctx, `
INSERT INTO samples (endpoint_id, ts, cpu_pct, mem_pct, mem_used, rx_rate, tx_rate, disk_pct, swap_pct, max_temp, io_read_bps, io_write_bps, posture_fails, pending_updates, payload)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer insert.Close()

	insertEvent, err := tx.PrepareContext(ctx, `
INSERT INTO events (endpoint_id, ts, type, message, org_id) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer insertEvent.Close()

	for _, snap := range snaps {
		if snap == nil || snap.AgentID == "" {
			continue
		}
		ts := snap.Timestamp.Unix()
		if _, err := upsert.ExecContext(ctx, snap.AgentID, snap.Hostname,
			snap.Host.OS, snap.Host.Platform, snap.Host.Arch,
			snap.CPU.Cores, snap.Memory.Total, snap.AgentVersion, orgID, ts, ts); err != nil {
			return fmt.Errorf("upsert endpoint: %w", err)
		}

		payload, err := json.Marshal(snap)
		if err != nil {
			return err
		}
		var swapPct float64
		if snap.Memory.SwapTotal > 0 {
			swapPct = float64(snap.Memory.SwapUsed) / float64(snap.Memory.SwapTotal) * 100
		}
		var maxTemp float64
		for _, t := range snap.Hardware.Temps {
			if t.Celsius > maxTemp {
				maxTemp = t.Celsius
			}
		}
		var ioRead, ioWrite float64
		for _, d := range snap.Hardware.DiskIO {
			ioRead += d.ReadBps
			ioWrite += d.WriteBps
		}
		postureFails := 0
		for _, p := range snap.Posture {
			if p.Status == "fail" {
				postureFails++
			}
		}
		if _, err := insert.ExecContext(ctx, snap.AgentID, ts,
			snap.CPU.TotalPercent, snap.Memory.UsedPercent, snap.Memory.Used,
			snap.Network.RxRate, snap.Network.TxRate, maxDiskPct(snap.Disks),
			swapPct, maxTemp, ioRead, ioWrite,
			postureFails, snap.Health.PendingUpdates, payload); err != nil {
			return fmt.Errorf("insert sample: %w", err)
		}
		for _, ev := range snap.Events {
			if _, err := insertEvent.ExecContext(ctx, snap.AgentID, ts, ev.Type, ev.Message, orgID); err != nil {
				return fmt.Errorf("insert event: %w", err)
			}
		}
		if snap.Inventory != nil {
			pkgs, err := json.Marshal(snap.Inventory.Packages)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
INSERT INTO inventory (endpoint_id, ts, kernel, manager, packages) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(endpoint_id) DO UPDATE SET ts=excluded.ts, kernel=excluded.kernel,
	manager=excluded.manager, packages=excluded.packages`,
				snap.AgentID, ts, snap.Inventory.Kernel, snap.Inventory.Manager, pkgs); err != nil {
				return fmt.Errorf("upsert inventory: %w", err)
			}
		}
	}
	return tx.Commit()
}

// Inventory returns an endpoint's last reported software inventory, or nil.
func (s *Store) Inventory(ctx context.Context, endpointID string) (*model.Inventory, time.Time, error) {
	var kernel, manager string
	var ts int64
	var pkgs []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT kernel, manager, packages, ts FROM inventory WHERE endpoint_id = ?`,
		endpointID).Scan(&kernel, &manager, &pkgs, &ts)
	if err == sql.ErrNoRows {
		return nil, time.Time{}, nil
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	inv := &model.Inventory{Kernel: kernel, Manager: manager}
	if err := json.Unmarshal(pkgs, &inv.Packages); err != nil {
		return nil, time.Time{}, err
	}
	return inv, time.Unix(ts, 0).UTC(), nil
}

func maxDiskPct(disks []model.DiskMetrics) float64 {
	var m float64
	for _, d := range disks {
		if d.UsedPercent > m {
			m = d.UsedPercent
		}
	}
	return m
}

// Endpoints lists known endpoints with their latest headline metrics, scoped
// to the given orgs (nil = all orgs).
func (s *Store) Endpoints(ctx context.Context, orgIDs []string) ([]model.EndpointSummary, error) {
	filter, args := orgFilter("e.org_id", orgIDs)
	rows, err := s.db.QueryContext(ctx, `
SELECT e.id, e.org_id, e.hostname, e.os, e.platform, e.arch, e.cores, e.mem_total, e.agent_version,
       e.first_seen, e.last_seen,
       COALESCE(sm.cpu_pct, 0), COALESCE(sm.mem_pct, 0)
FROM endpoints e
LEFT JOIN samples sm ON sm.id = (
	SELECT id FROM samples WHERE endpoint_id = e.id ORDER BY ts DESC LIMIT 1
)
WHERE 1=1`+filter+`
ORDER BY e.hostname`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := time.Now()
	var out []model.EndpointSummary
	for rows.Next() {
		var ep model.EndpointSummary
		var first, last int64
		if err := rows.Scan(&ep.ID, &ep.OrgID, &ep.Hostname, &ep.OS, &ep.Platform, &ep.Arch,
			&ep.Cores, &ep.MemTotal, &ep.AgentVersion, &first, &last, &ep.CPUPercent, &ep.MemPercent); err != nil {
			return nil, err
		}
		ep.FirstSeen = time.Unix(first, 0).UTC()
		ep.LastSeen = time.Unix(last, 0).UTC()
		ep.Online = now.Sub(ep.LastSeen) < onlineWindow
		out = append(out, ep)
	}
	return out, rows.Err()
}

// DeleteEndpoint removes an endpoint and every trace of it: samples, events,
// alerts, and its agent token. Returns whether the endpoint existed.
func (s *Store) DeleteEndpoint(ctx context.Context, endpointID string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		`DELETE FROM samples WHERE endpoint_id = ?`,
		`DELETE FROM events WHERE endpoint_id = ?`,
		`DELETE FROM alerts WHERE endpoint_id = ?`,
		`DELETE FROM agent_tokens WHERE agent_id = ?`,
		`DELETE FROM inventory WHERE endpoint_id = ?`,
		`DELETE FROM edges WHERE src_id = ?1 OR dst_id = ?1`,
	} {
		if _, err := tx.ExecContext(ctx, stmt, endpointID); err != nil {
			return false, err
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM endpoints WHERE id = ?`, endpointID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, tx.Commit()
}

// EndpointOrg returns the org an endpoint belongs to, or "" if unknown.
func (s *Store) EndpointOrg(ctx context.Context, endpointID string) (string, error) {
	var orgID string
	err := s.db.QueryRowContext(ctx,
		`SELECT org_id FROM endpoints WHERE id = ?`, endpointID).Scan(&orgID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return orgID, err
}

// Latest returns the most recent full snapshot for an endpoint, or nil if the
// endpoint is unknown.
func (s *Store) Latest(ctx context.Context, endpointID string) (*model.Snapshot, error) {
	var payload []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT payload FROM samples WHERE endpoint_id = ? ORDER BY ts DESC LIMIT 1`,
		endpointID).Scan(&payload)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var snap model.Snapshot
	if err := json.Unmarshal(payload, &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

// History returns averaged points bucketed to stepSeconds over [from, to].
func (s *Store) History(ctx context.Context, endpointID string, from, to time.Time, stepSeconds int) ([]model.HistoryPoint, error) {
	if stepSeconds < 1 {
		stepSeconds = 1
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT (ts / ?) * ? AS bucket,
       AVG(cpu_pct), AVG(mem_pct), AVG(mem_used), AVG(rx_rate), AVG(tx_rate), AVG(disk_pct),
       AVG(max_temp), AVG(io_read_bps), AVG(io_write_bps)
FROM samples
WHERE endpoint_id = ? AND ts BETWEEN ? AND ?
GROUP BY bucket ORDER BY bucket`,
		stepSeconds, stepSeconds, endpointID, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.HistoryPoint
	for rows.Next() {
		var p model.HistoryPoint
		var memUsed float64
		if err := rows.Scan(&p.Timestamp, &p.CPUPercent, &p.MemPercent, &memUsed,
			&p.RxRate, &p.TxRate, &p.DiskPct,
			&p.MaxTemp, &p.IoReadBps, &p.IoWriteBps); err != nil {
			return nil, err
		}
		p.MemUsed = uint64(memUsed)
		out = append(out, p)
	}
	return out, rows.Err()
}

// Prune deletes samples and events older than the retention window and
// returns how many sample rows were removed.
func (s *Store) Prune(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().Add(-retention).Unix()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, cutoff); err != nil {
		return 0, err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM edges WHERE last_seen < ?`, cutoff); err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM samples WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---- topology edges ----

// UpsertEdge records one observed fleet-internal communication path and
// reports whether it was seen for the first time.
func (s *Store) UpsertEdge(ctx context.Context, orgID, srcID, dstID, process string, port int, ts int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO edges (org_id, src_id, dst_id, process, dst_port, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(src_id, dst_id, process, dst_port) DO UPDATE SET
	last_seen = MAX(edges.last_seen, excluded.last_seen), org_id = excluded.org_id`,
		orgID, srcID, dstID, process, port, ts, ts)
	if err != nil {
		return false, err
	}
	// SQLite reports 1 affected row for both insert and update; detect "new"
	// by whether first_seen == ts after the statement.
	_ = res
	var first int64
	err = s.db.QueryRowContext(ctx,
		`SELECT first_seen FROM edges WHERE src_id=? AND dst_id=? AND process=? AND dst_port=?`,
		srcID, dstID, process, port).Scan(&first)
	return err == nil && first == ts, err
}

// Edges returns internal edges seen since the given time, scoped to orgs.
func (s *Store) Edges(ctx context.Context, orgIDs []string, since time.Time) ([]model.TopoEdge, error) {
	filter, args := orgFilter("org_id", orgIDs)
	q := `SELECT src_id, dst_id, process, dst_port, MIN(first_seen), MAX(last_seen)
FROM edges WHERE last_seen >= ?` + filter + `
GROUP BY src_id, dst_id, process, dst_port ORDER BY src_id, dst_id`
	rows, err := s.db.QueryContext(ctx, q, append([]any{since.Unix()}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Merge per (src,dst) with the process/port list.
	merged := map[string]*model.TopoEdge{}
	var order []string
	for rows.Next() {
		var src, dst, process string
		var port int
		var first, last int64
		if err := rows.Scan(&src, &dst, &process, &port, &first, &last); err != nil {
			return nil, err
		}
		key := src + "|" + dst
		e, ok := merged[key]
		if !ok {
			e = &model.TopoEdge{Src: src, Dst: dst, Internal: true,
				FirstSeen: time.Unix(first, 0).UTC(), LastSeen: time.Unix(last, 0).UTC()}
			merged[key] = e
			order = append(order, key)
		}
		e.Processes = append(e.Processes, model.EdgeProcess{Process: process, Port: port})
		e.Count++
		if t := time.Unix(first, 0).UTC(); t.Before(e.FirstSeen) {
			e.FirstSeen = t
		}
		if t := time.Unix(last, 0).UTC(); t.After(e.LastSeen) {
			e.LastSeen = t
		}
	}
	out := make([]model.TopoEdge, 0, len(order))
	for _, k := range order {
		out = append(out, *merged[k])
	}
	return out, rows.Err()
}

// InsertServerEvent records a server-generated event (e.g. first-seen
// topology edges, which no single agent can observe).
func (s *Store) InsertServerEvent(ctx context.Context, orgID, endpointID, typ, message string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO events (endpoint_id, ts, type, message, org_id) VALUES (?, ?, ?, ?, ?)`,
		endpointID, time.Now().Unix(), typ, message, orgID)
	return err
}

// ---- events ----

// Events returns recent events, newest first, scoped to orgs (nil = all).
// endpointID "" means fleet-wide.
func (s *Store) Events(ctx context.Context, endpointID string, orgIDs []string, limit int) ([]model.StoredEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	filter, fargs := orgFilter("ev.org_id", orgIDs)
	q := `
SELECT ev.id, ev.org_id, ev.endpoint_id, COALESCE(e.hostname, ev.endpoint_id), ev.ts, ev.type, ev.message
FROM events ev LEFT JOIN endpoints e ON e.id = ev.endpoint_id
WHERE 1=1` + filter
	args := fargs
	if endpointID != "" {
		q += ` AND ev.endpoint_id = ?`
		args = append(args, endpointID)
	}
	q += ` ORDER BY ev.id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.StoredEvent
	for rows.Next() {
		var ev model.StoredEvent
		var ts int64
		if err := rows.Scan(&ev.ID, &ev.OrgID, &ev.EndpointID, &ev.Hostname, &ts, &ev.Type, &ev.Message); err != nil {
			return nil, err
		}
		ev.Timestamp = time.Unix(ts, 0).UTC()
		out = append(out, ev)
	}
	return out, rows.Err()
}

// ---- alerts ----

// OpenAlert returns the id of the firing alert for (rule, endpoint), or 0.
func (s *Store) OpenAlert(ctx context.Context, rule, endpointID string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM alerts WHERE rule = ? AND endpoint_id = ? AND state = 'firing'`,
		rule, endpointID).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}

func (s *Store) FireAlert(ctx context.Context, a model.Alert) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO alerts (rule, endpoint_id, hostname, state, message, value, started_at, org_id)
VALUES (?, ?, ?, 'firing', ?, ?, ?, ?)`,
		a.Rule, a.EndpointID, a.Hostname, a.Message, a.Value, a.StartedAt.Unix(), a.OrgID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ResolveAlert(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE alerts SET state = 'resolved', resolved_at = ? WHERE id = ?`,
		time.Now().Unix(), id)
	return err
}

// Alerts returns alerts, newest first, scoped to orgs (nil = all). state ""
// means all states.
func (s *Store) Alerts(ctx context.Context, state string, orgIDs []string, limit int) ([]model.Alert, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	filter, args := orgFilter("org_id", orgIDs)
	q := `SELECT id, org_id, rule, endpoint_id, hostname, state, message, value, started_at, resolved_at
FROM alerts WHERE 1=1` + filter
	if state != "" {
		q += ` AND state = ?`
		args = append(args, state)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Alert
	for rows.Next() {
		var a model.Alert
		var started int64
		var resolved sql.NullInt64
		if err := rows.Scan(&a.ID, &a.OrgID, &a.Rule, &a.EndpointID, &a.Hostname, &a.State,
			&a.Message, &a.Value, &started, &resolved); err != nil {
			return nil, err
		}
		a.StartedAt = time.Unix(started, 0).UTC()
		if resolved.Valid {
			t := time.Unix(resolved.Int64, 0).UTC()
			a.ResolvedAt = &t
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---- statistics for the alert engine ----

// metricColumns whitelists rule metrics onto sample columns; the metric name
// is interpolated into SQL so it must never come from untrusted input
// directly.
var metricColumns = map[string]string{
	"cpu_pct":      "cpu_pct",
	"mem_pct":      "mem_pct",
	"disk_pct":     "disk_pct",
	"swap_pct":     "swap_pct",
	"rx_rate":      "rx_rate",
	"tx_rate":      "tx_rate",
	"max_temp_c":      "max_temp",
	"io_read_bps":     "io_read_bps",
	"io_write_bps":    "io_write_bps",
	"posture_fails":   "posture_fails",
	"pending_updates": "pending_updates",
}

// WindowAvg returns the average of a metric over the trailing window and the
// number of samples in it.
func (s *Store) WindowAvg(ctx context.Context, endpointID, metric string, window time.Duration) (float64, int, error) {
	col, ok := metricColumns[metric]
	if !ok {
		return 0, 0, fmt.Errorf("unknown metric %q", metric)
	}
	var avg sql.NullFloat64
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT AVG(`+col+`), COUNT(*) FROM samples WHERE endpoint_id = ? AND ts >= ?`,
		endpointID, time.Now().Add(-window).Unix()).Scan(&avg, &n)
	if err != nil {
		return 0, 0, err
	}
	return avg.Float64, n, nil
}

// Baseline returns mean, standard deviation, and sample count for a metric
// over [from, to] — the "normal" the anomaly detector compares against.
func (s *Store) Baseline(ctx context.Context, endpointID, metric string, from, to time.Time) (mean, std float64, n int, err error) {
	col, ok := metricColumns[metric]
	if !ok {
		return 0, 0, 0, fmt.Errorf("unknown metric %q", metric)
	}
	var avg, avgSq sql.NullFloat64
	err = s.db.QueryRowContext(ctx,
		`SELECT AVG(`+col+`), AVG(`+col+`*`+col+`), COUNT(*) FROM samples
		 WHERE endpoint_id = ? AND ts BETWEEN ? AND ?`,
		endpointID, from.Unix(), to.Unix()).Scan(&avg, &avgSq, &n)
	if err != nil {
		return 0, 0, 0, err
	}
	mean = avg.Float64
	if variance := avgSq.Float64 - mean*mean; variance > 0 {
		std = math.Sqrt(variance)
	}
	return mean, std, n, nil
}

// ---- per-agent tokens ----

// SetAgentToken stores the hash of a newly issued agent token and the org the
// agent enrolled into.
func (s *Store) SetAgentToken(ctx context.Context, agentID, tokenHash, orgID string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO agent_tokens (agent_id, token_hash, created_at, org_id) VALUES (?, ?, ?, ?)
ON CONFLICT(agent_id) DO UPDATE SET token_hash=excluded.token_hash,
	created_at=excluded.created_at, org_id=excluded.org_id`,
		agentID, tokenHash, time.Now().Unix(), orgID)
	return err
}

// AgentToken returns the stored hash and org for an agent; hash "" means not
// enrolled.
func (s *Store) AgentToken(ctx context.Context, agentID string) (hash, orgID string, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT token_hash, org_id FROM agent_tokens WHERE agent_id = ?`, agentID).Scan(&hash, &orgID)
	if err == sql.ErrNoRows {
		return "", "", nil
	}
	return hash, orgID, err
}

// DeleteAgentToken revokes an agent's token. Returns whether one existed.
func (s *Store) DeleteAgentToken(ctx context.Context, agentID string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM agent_tokens WHERE agent_id = ?`, agentID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
