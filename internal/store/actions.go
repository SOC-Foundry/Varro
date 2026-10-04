package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// EnqueueAction records an operator-issued response action and returns its id.
func (s *Store) EnqueueAction(ctx context.Context, endpointID, typ, arg, issuedBy string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO actions (endpoint_id, type, arg, status, issued_by, issued_at)
VALUES (?, ?, ?, 'pending', ?, ?)`,
		endpointID, typ, arg, issuedBy, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ClaimActions returns an endpoint's pending actions and marks them sent, so a
// crashed agent's commands are retried but a slow-acking one isn't duplicated
// mid-flight. Capped per poll.
func (s *Store) ClaimActions(ctx context.Context, endpointID string) ([]model.Action, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, type, arg FROM actions
WHERE endpoint_id = ? AND status = 'pending' ORDER BY id LIMIT 20`, endpointID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Action
	for rows.Next() {
		var a model.Action
		if err := rows.Scan(&a.ID, &a.Type, &a.Arg); err != nil {
			return nil, err
		}
		a.EndpointID = endpointID
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, a := range out {
		s.db.ExecContext(ctx, `UPDATE actions SET status='sent' WHERE id = ? AND status='pending'`, a.ID)
	}
	return out, nil
}

// AckAction records an executed action's outcome.
func (s *Store) AckAction(ctx context.Context, id int64, ok bool, result string) error {
	status := model.ActionDone
	if !ok {
		status = model.ActionFailed
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE actions SET status=?, result=?, done_at=? WHERE id=?`,
		status, result, time.Now().Unix(), id)
	return err
}

// ActionEndpoint returns the endpoint an action targets (for ack authorization).
func (s *Store) ActionEndpoint(ctx context.Context, id int64) (string, error) {
	var ep string
	err := s.db.QueryRowContext(ctx, `SELECT endpoint_id FROM actions WHERE id = ?`, id).Scan(&ep)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return ep, err
}

// Actions lists an endpoint's recent actions, newest first.
func (s *Store) Actions(ctx context.Context, endpointID string, limit int) ([]model.Action, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, endpoint_id, type, arg, status, COALESCE(result,''), issued_by, issued_at, done_at
FROM actions WHERE endpoint_id = ? ORDER BY id DESC LIMIT ?`, endpointID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Action
	for rows.Next() {
		var a model.Action
		var issued int64
		var done sql.NullInt64
		if err := rows.Scan(&a.ID, &a.EndpointID, &a.Type, &a.Arg, &a.Status, &a.Result,
			&a.IssuedBy, &issued, &done); err != nil {
			return nil, err
		}
		a.IssuedAt = time.Unix(issued, 0).UTC()
		if done.Valid {
			t := time.Unix(done.Int64, 0).UTC()
			a.DoneAt = &t
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
