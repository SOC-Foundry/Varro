package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// GetRollout returns the staged agent-rollout config, or a zero value (all fields
// empty) when none has been set.
func (s *Store) GetRollout(ctx context.Context) (model.AgentRollout, error) {
	var r model.AgentRollout
	var ids string
	err := s.db.QueryRowContext(ctx,
		`SELECT stable_version, canary_version, canary_ids, updated_at FROM agent_rollout WHERE id = 1`).
		Scan(&r.StableVersion, &r.CanaryVersion, &ids, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return model.AgentRollout{CanaryIDs: []string{}}, nil
	}
	if err != nil {
		return r, err
	}
	if ids != "" {
		json.Unmarshal([]byte(ids), &r.CanaryIDs)
	}
	if r.CanaryIDs == nil {
		r.CanaryIDs = []string{}
	}
	return r, nil
}

// SetRollout upserts the singleton rollout config.
func (s *Store) SetRollout(ctx context.Context, r model.AgentRollout) error {
	ids, err := json.Marshal(r.CanaryIDs)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO agent_rollout (id, stable_version, canary_version, canary_ids, updated_at)
VALUES (1, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
  stable_version = excluded.stable_version,
  canary_version = excluded.canary_version,
  canary_ids = excluded.canary_ids,
  updated_at = excluded.updated_at`,
		r.StableVersion, r.CanaryVersion, string(ids), time.Now().Unix())
	return err
}
