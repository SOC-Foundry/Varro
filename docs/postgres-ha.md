# Postgres HA — streaming replica & failover

Production runs a primary + one async streaming standby so a lost database VM no
longer means data loss or an extended outage. (Collectors are already HA behind
the load balancer; this removes the last single point of failure.)

## Topology

| Role | Host | Internal IP |
|------|------|-------------|
| Primary | `varro-pg` | `10.128.0.10` |
| Standby (hot read replica) | `varro-pg-2` | `10.128.0.12` |

- **Replication:** async streaming, physical slot `standby1`, role `replicator`.
  The link is TLS (`hostssl` on the primary; the standby connects `sslmode=require`).
- **Failover-ready:** the standby already serves the Varro **CA-signed** server
  cert (`/etc/postgresql/15/main/server.{crt,key}`, copied from the primary) and
  listens on `10.128.0.12`. Collectors use `sslmode=verify-ca`, which validates
  the CA (not the hostname), so the same cert is valid on the standby. The
  standby's `pg_hba.conf` is a copy of the primary's, so it already permits the
  collector's `hostssl` connections.
- **Set up 2026-10-12.** No primary restart was needed (`wal_level` was already
  `replica`).

## Monitor replication

On the **primary**:
```sql
SELECT client_addr, state, sync_state, write_lag, replay_lag FROM pg_stat_replication;
SELECT slot_name, active, restart_lsn FROM pg_replication_slots;
```
Healthy = one row, `state=streaming`, small `replay_lag`, slot `active=t`.
(Watch the slot: an inactive slot retains WAL on the primary and can fill its
disk — if the standby is decommissioned, drop the slot:
`SELECT pg_drop_replication_slot('standby1');`.)

## Failover (promote the standby)

1. **Confirm the primary is really down** (avoid split-brain — never promote while
   the primary still serves writes).
2. **Promote** on `varro-pg-2`:
   ```sh
   sudo -u postgres psql -c "SELECT pg_promote();"
   # verify it left recovery:
   sudo -u postgres psql -tAc "SELECT pg_is_in_recovery();"   # -> f
   ```
3. **Repoint the collectors** — update `VARRO_DB_URL` host `10.128.0.10` →
   `10.128.0.12` in the root drop-in on **both** collectors, then restart:
   ```sh
   sudo sudoedit /etc/systemd/system/varro-server.service.d/postgres.conf   # host=10.128.0.12
   sudo systemctl daemon-reload && sudo systemctl restart varro-server
   ```
   (Agents disk-spool and the pgx pool reconnects during the swap, so in-flight
   telemetry is not lost.)
4. **Verify:** `curl -s https://varro.socfoundry.com/api/v1/health` → 200, and the
   dashboard loads.

## After failover — rebuild redundancy

The old primary (`varro-pg`), once recovered, is stale and must be rebuilt as a
standby of the new primary (`varro-pg-2`) — same procedure as the initial setup
(`pg_basebackup` from `10.128.0.12`, a new slot, `-R`). Then you're HA again,
with the direction reversed.

## Caveats

- **Async** replication: a hard primary loss can lose the last few in-flight
  transactions (sub-second at normal lag). Acceptable for telemetry; switch to
  synchronous (`synchronous_standby_names`) only if zero-loss is required (it adds
  write latency and makes the primary block if the standby is down).
- Promotion is **manual** (no automatic failover / Patroni). For auto-failover,
  consider Patroni or Cloud SQL later.
- Keep the standby's server cert in sync if the CA/cert is ever rotated.
