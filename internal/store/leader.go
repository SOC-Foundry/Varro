package store

import (
	"context"
	"time"
)

// TryAcquireLeader attempts to acquire or renew the single leader lease for
// `instanceID`, valid for ttl. It returns whether this instance currently holds
// the lease. Used so that, when multiple collectors run behind a load balancer,
// exactly one runs the singleton background jobs (alert engine, retention,
// backups, vuln scans) while all of them serve ingest/API.
//
// The upsert's WHERE grants the lease only when the caller already holds it (a
// renewal) or the current lease has expired (a takeover); otherwise a valid
// holder keeps it. Works identically on SQLite (single node always wins) and
// Postgres (true contention across collectors).
func (s *Store) TryAcquireLeader(ctx context.Context, instanceID string, ttl time.Duration) (bool, error) {
	now := time.Now().Unix()
	exp := time.Now().Add(ttl).Unix()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO leader_lease (id, holder, expires_at) VALUES (1, ?, ?)
ON CONFLICT (id) DO UPDATE SET holder = excluded.holder, expires_at = excluded.expires_at
WHERE leader_lease.holder = excluded.holder OR leader_lease.expires_at < ?`,
		instanceID, exp, now)
	if err != nil {
		return false, err
	}
	var holder string
	if err := s.db.QueryRowContext(ctx,
		`SELECT holder FROM leader_lease WHERE id = 1`).Scan(&holder); err != nil {
		return false, err
	}
	return holder == instanceID, nil
}
