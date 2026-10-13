# Postgres automatic failover (pg_auto_failover)

Status: **mechanics VALIDATED on throwaway test VMs (2026-10-13); prod cutover
pending a maintenance window.** Prod (`varro-pg` / `varro-pg-2`) is NOT yet
touched. This extends the existing manual-failover HA (see
[postgres-ha.md](postgres-ha.md)) with automatic promotion.

## What was validated (2026-10-13)

Three temp VMs (`tpg-mon`/`tpg1`/`tpg2`, debian-12, e2-small, PG 15.19 + pg_autoctl
2.2 from PGDG) — a fresh (greenfield) 1-monitor + 2-data cluster:

- Brought up monitor + primary (node_1) + secondary (node_2); `show state`
  healthy, same LSN.
- Wrote a marker through the collector-style DSN
  `postgres://…@10.128.0.15,10.128.0.14:5432/…?target_session_attrs=read-write`
  → routed to the primary.
- **Hard-killed the primary (stopped the whole VM).** The monitor demoted it and
  auto-promoted the secondary to read-write in **~40s** (timeline bumped 1→2).
- The **same DSN transparently reached the new primary** with zero config change;
  the marker had replicated (no data loss) and new writes succeeded.
- Tore the temp VMs down.

Conclusion: pg_auto_failover delivers exactly what the collectors need —
automatic promotion + client-side primary discovery via libpq multi-host
`target_session_attrs=read-write` (pgx supports this). 

**Gotcha found:** `pg_autoctl create monitor` only auto-authorizes the monitor's
OWN ip (`/32`) in its `pg_hba.conf`. The data nodes can't register until you add
their subnet:
`host pg_auto_failover autoctl_node 10.128.0.0/20 trust` → `SELECT pg_reload_conf()`
on the monitor. (Prod: scope to the exact data-node IPs, not a broad /20.)

## Why pg_auto_failover

Chosen over Patroni+etcd (fewer moving parts — no separate DCS quorum to run)
and Cloud SQL (no migration). A single **monitor** node is the arbiter of who is
primary; it health-checks the data nodes and orchestrates promotion with fencing,
so there is no split-brain. Clients find the current primary with a libpq
multi-host connection string — no HAProxy/VIP needed.

## Topology (target)

| Role | Node | Notes |
|------|------|-------|
| Monitor | `varro-pg-mon` (new, e2-small) | runs a dedicated Postgres + the `pgautofailover` extension; the HA arbiter |
| Data (primary) | `varro-pg` (10.128.0.10) | existing prod primary, adopted |
| Data (secondary) | `varro-pg-2` (10.128.0.12) | existing standby, re-registered |

Collectors connect with a multi-host DSN so libpq/pgx routes writes to whoever is
currently primary:

```
postgres://varro:...@10.128.0.10,10.128.0.12:5432/varro?target_session_attrs=read-write&sslmode=verify-ca&sslrootcert=/etc/varro/pg-ca.crt
```

`target_session_attrs=read-write` makes the driver skip a host that is in
recovery (the standby) and use the read-write one (the primary) — so after a
failover the pool reconnects to the promoted node with no config change.

## Environment facts (verified 2026-10-13)

- Prod PG VMs: Debian 12 bookworm, PostgreSQL 15.19, PGDG apt repo present.
- Packages: `postgresql-15-auto-failover` + `pg-auto-failover-cli` (apt).
- `pg_autoctl` not yet installed anywhere.

## Validation plan (test VMs — no prod impact)

Temp VMs `tpg-mon`, `tpg1`, `tpg2` (debian-12, e2-small, us-central1-a):

1. Install `postgresql-15 postgresql-15-auto-failover pg-auto-failover-cli` on all.
2. Monitor: `pg_autoctl create monitor --pgdata /var/lib/postgresql/15/monitor --auth trust --ssl-self-signed` → run as systemd (`pg_autoctl -q show systemd | sudo tee /etc/systemd/system/pgautofailover.service`).
3. tpg1: `pg_autoctl create postgres --pgdata /var/lib/postgresql/15/ha --monitor 'postgres://autoctl_node@<MON_IP>/pg_auto_failover?sslmode=require' --ssl-self-signed --hostname <tpg1_ip>` → becomes **single/primary**.
4. tpg2: same `create postgres` → monitor assigns **secondary** (auto `pg_basebackup`).
5. `pg_autoctl show state` → primary + secondary, healthy.
6. **Failover test**: stop Postgres on tpg1 (`pg_autoctl stop` or kill the VM). Monitor promotes tpg2 within its timeout; `show state` flips.
7. **Client test**: `psql 'host=tpg1,tpg2 ... target_session_attrs=read-write'` keeps reaching the primary across the failover.
8. Tear the temp VMs down.

## Prod cutover (needs a maintenance window — NOT yet done)

The validation above was **greenfield** (fresh `initdb` nodes). Prod has an
existing populated primary + hand-built standby, so the cutover has one extra
risk the test didn't cover: getting prod data under pg_autoctl's management.
Two options:

**Option A — adopt in place (less data movement, more fiddly).** `pg_autoctl
create postgres` can adopt an existing PGDATA, but it takes over PG service/config
management and briefly restarts Postgres. Steps:
1. Create `varro-pg-mon` (e2-small); bring up the monitor; open its pg_hba to the
   two data-node IPs (the gotcha above).
2. On `varro-pg` (primary): install pkgs, `pg_autoctl create postgres` adopting the
   existing PGDATA → registers as primary (brief restart; collector pool reconnects,
   agents disk-spool — same as any PG restart).
3. On `varro-pg-2`: tear down the old manual slot/standby, `pg_autoctl create
   postgres` → managed secondary (re-basebackups from the primary).
4. Point both collectors' `VARRO_DB_URL` at the multi-host DSN; restart.
5. `pg_autoctl perform failover` as a controlled drill; confirm collectors ride it.

**Option B — greenfield + migrate (cleanest, matches what was validated).** Stand
up a fresh pg_auto_failover cluster (new monitor + 2 new data VMs), migrate data in
(`pg_dump | pg_restore`, short write-freeze), repoint collectors, retire the old
pair. More VMs/data movement but every step is the already-validated path.

**Recommendation:** validate Option A's adopt-existing step on one more throwaway
VM pair (seed it with a `pg_basebackup` of prod first) before trusting it on prod;
otherwise take Option B. Either way it is a scheduled maintenance window, not an
inline change. Keep the Varro CA server cert on the data nodes (collectors use
`sslmode=verify-ca`).

## Caveats

- pg_autoctl wants to **own** PG config/service management; after cutover, do not
  hand-edit postgresql.conf/pg_hba — change them via `pg_autoctl` or its config.
- The monitor is a new SPOF for *failover decisions* (not for serving data — if
  the monitor is down, the current primary keeps serving; only automatic failover
  pauses). Keep it backed up; it holds only HA state.
- Keep the Varro CA-signed server cert in place on the data nodes (collectors use
  `sslmode=verify-ca`); pg_autoctl's `--ssl-self-signed` is for the node↔monitor
  link, not the collector↔data link.
