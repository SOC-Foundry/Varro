package store

import (
	"context"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// rawHistoryHorizon: history requests spanning longer than this are served from
// the hourly rollup table instead of raw samples, so charts extend past the raw
// retention window (and stay cheap).
const rawHistoryHorizon = 36 * time.Hour

// RollupSamples folds raw samples since `from` into hourly per-endpoint averages
// in sample_rollups (idempotent upsert — safe to re-run over overlapping windows,
// and backfills on first run). Run before pruning raw samples.
func (s *Store) RollupSamples(ctx context.Context, from time.Time) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO sample_rollups
  (endpoint_id, bucket, cpu_pct, mem_pct, mem_used, rx_rate, tx_rate, disk_pct, max_temp, io_read_bps, io_write_bps)
SELECT endpoint_id, (ts / 3600) * 3600 AS bucket,
       AVG(cpu_pct), AVG(mem_pct), AVG(mem_used), AVG(rx_rate), AVG(tx_rate), AVG(disk_pct),
       AVG(max_temp), AVG(io_read_bps), AVG(io_write_bps)
FROM samples WHERE ts >= ?
GROUP BY endpoint_id, bucket
ON CONFLICT(endpoint_id, bucket) DO UPDATE SET
  cpu_pct = excluded.cpu_pct, mem_pct = excluded.mem_pct, mem_used = excluded.mem_used,
  rx_rate = excluded.rx_rate, tx_rate = excluded.tx_rate, disk_pct = excluded.disk_pct,
  max_temp = excluded.max_temp, io_read_bps = excluded.io_read_bps, io_write_bps = excluded.io_write_bps`,
		from.Unix())
	return err
}

// historyFromRollups serves hourly history points from the rollup table.
func (s *Store) historyFromRollups(ctx context.Context, endpointID string, from, to time.Time) ([]model.HistoryPoint, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT bucket, cpu_pct, mem_pct, mem_used, rx_rate, tx_rate, disk_pct, max_temp, io_read_bps, io_write_bps
FROM sample_rollups WHERE endpoint_id = ? AND bucket BETWEEN ? AND ? ORDER BY bucket`,
		endpointID, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.HistoryPoint
	for rows.Next() {
		var p model.HistoryPoint
		var memUsed float64
		if err := rows.Scan(&p.Timestamp, &p.CPUPercent, &p.MemPercent, &memUsed,
			&p.RxRate, &p.TxRate, &p.DiskPct, &p.MaxTemp, &p.IoReadBps, &p.IoWriteBps); err != nil {
			return nil, err
		}
		p.MemUsed = uint64(memUsed)
		out = append(out, p)
	}
	return out, rows.Err()
}
