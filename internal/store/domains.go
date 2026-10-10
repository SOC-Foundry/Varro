package store

import (
	"context"
	"time"
)

// MarkDomainSeen records that an org has been observed talking to a domain and
// reports whether this is the first time (isNew). Used to flag newly-seen
// external domains — a classic exfiltration / C2 signal. Idempotent via
// ON CONFLICT DO NOTHING; isNew is true only on the inserting call.
func (s *Store) MarkDomainSeen(ctx context.Context, orgID, domain string) (isNew bool, err error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO seen_domains (org_id, domain, first_seen) VALUES (?, ?, ?)
		 ON CONFLICT DO NOTHING`,
		orgID, domain, time.Now().Unix())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
