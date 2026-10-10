package store

import (
	"context"
	"database/sql"
	"time"
)

// Topology snapshots power the time-travel slider: the collector periodically
// serializes each org's topology graph so the dashboard can replay history.

// SaveTopologySnapshot stores one serialized topology graph for an org.
func (s *Store) SaveTopologySnapshot(ctx context.Context, orgID string, ts int64, data []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO topology_snapshots (org_id, ts, data) VALUES (?, ?, ?)`, orgID, ts, data)
	return err
}

// TopologyAt returns the most recent snapshot at or before ts. Time-travel is
// per-org, so a nil/multi-org scope (instance-admin "all orgs") returns nil.
func (s *Store) TopologyAt(ctx context.Context, scope []string, ts int64) ([]byte, error) {
	if len(scope) != 1 {
		return nil, nil
	}
	var data []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT data FROM topology_snapshots WHERE org_id = ? AND ts <= ? ORDER BY ts DESC LIMIT 1`,
		scope[0], ts).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return data, err
}

// TopologyTimeline returns available snapshot timestamps for an org, newest
// first (capped).
func (s *Store) TopologyTimeline(ctx context.Context, scope []string) ([]int64, error) {
	if len(scope) != 1 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT ts FROM topology_snapshots WHERE org_id = ? ORDER BY ts DESC LIMIT 500`, scope[0])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var t int64
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// PruneTopologySnapshots trims snapshots older than the retention window.
func (s *Store) PruneTopologySnapshots(ctx context.Context, retention time.Duration) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM topology_snapshots WHERE ts < ?`, time.Now().Add(-retention).Unix())
	return err
}
