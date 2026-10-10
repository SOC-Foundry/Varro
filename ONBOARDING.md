# Varro — engineer onboarding

Orientation for working on the **running** Varro system (not the product pitch —
see [README.md](README.md) for what Varro does and how to run it from source).

## What it is, in one line

A single Go binary (`varro`) that is both the endpoint **agent** and the central
**collector** (ingest API + web dashboard + REST + Prometheus). Pure Go, no cgo.

## Production environment

SOC Foundry, GCP project **`varro-510502`**, zone `us-central1-a`. Operate it as
`david@socfoundry.com` (`gcloud config set account …`; always pass
`--project varro-510502`).

| Host | Role | Internal IP |
|------|------|-------------|
| `varro-collector` (e2-micro) | collector + Caddy (TLS) + a self-monitoring agent. Runs as a systemd **DynamicUser**. | `10.128.0.2` |
| `varro-pg` (e2-small) | PostgreSQL 15 (the production datastore) | `10.128.0.10` |

- Public URL: **https://varro.socfoundry.com** (Caddy terminates TLS → collector
  on `127.0.0.1:9477`). DNS is a Cloudflare A record (DNS-only).
- Dashboard requires Google sign-in; the first signer + `--admin-emails` are
  instance admins.
- Secrets (master token, OAuth secret, DB URL) live **only** in the collector's
  root-readable systemd unit / drop-ins — never in the repo.

## Build / test / release

```sh
go build ./...              # or: go build -o varro ./cmd/varro
go test ./...               # fast, pure Go
make cross                  # cross-compile agents (linux/darwin/windows) -> dist/
```

Releases publish automatically when a `v*` tag is pushed
(`.github/workflows/release.yml` → cross-built binaries + signed checksums on
GitHub Releases). **Agents auto-upgrade** to the collector's version, so the
deploy flow is: tag → push → build the collector binary → swap it on the VM.

Deploying the collector (atomic, avoids "text file busy"):

```sh
# build with the version stamped
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=vX.Y.Z" -o varro-new ./cmd/varro
gcloud compute scp --project varro-510502 --zone us-central1-a varro-new varro-collector:/tmp/varro-new
gcloud compute ssh  --project varro-510502 --zone us-central1-a varro-collector --command '
  BIN=$(sudo systemctl show -p ExecStart varro-server | sed -n "s/.*path=\([^ ;]*\).*/\1/p")
  sudo cp /tmp/varro-new "$BIN.new" && sudo chmod +x "$BIN.new" && sudo mv -f "$BIN.new" "$BIN"
  sudo systemctl restart varro-server && systemctl is-active varro-server'
```

## Data store — Postgres

Production runs on **PostgreSQL** (migrated from SQLite). Varro is
datastore-agnostic: `store.Open` picks Postgres when the DSN starts with
`postgres://`, else SQLite; the collector gets its DSN from `VARRO_DB_URL` (set
in a root-only systemd drop-in), which overrides the `--db` SQLite flag.

**Full runbook: [docs/postgres-setup.md](docs/postgres-setup.md)** — provisioning
`varro-pg`, PG install, TLS (private CA, `verify-ca`, `hostssl`-enforced), the
SQLite→Postgres cutover (`varro migrate-db`), pointing the collector at it, daily
GCS backups, restore, and rollback.

Day-to-day essentials:

- **Connection is TLS-only.** Collector DSN uses
  `sslmode=verify-ca&sslrootcert=/etc/varro/pg-ca.crt`; `pg_hba` is `hostssl`
  scoped to the collector IP. Plaintext is rejected.
- **Backups:** `varro-pg` runs `varro-pg-backup.timer` daily (03:30 UTC),
  `pg_dump | gzip` → `gs://varro-backups-510502/postgres/` via the VM metadata
  SA token (no keys). 30-day lifecycle rotates them. Restore drill is documented
  and has passed.
- **Rollback to SQLite:** remove the `postgres.conf` drop-in on the collector and
  restart — the ~370 MB `varro.db.sqlite-backup` is retained.
- **Schema:** auto-created/migrated on connect (`store.migrate()`), dialect-aware
  (`internal/store/db.go` rebinds `?`→`$n`, maps `INTEGER`→`BIGINT`, etc.). No
  manual DDL.

## Repo layout

```
cmd/varro/            entry point, flag wiring, subcommand dispatch, version
internal/model/       shared types (snapshots, events, alerts, actions, tokens)
internal/collect/     gopsutil + security collectors, eBPF/DNS/SNI watchers
internal/agent/       sample loop, enrollment, disk spool, host isolation
internal/ebpf/        bpf2go exec sensor (C + generated Go)
internal/store/       SQLite/Postgres persistence, dialect wrapper, migrate-db
internal/server/      ingest/query API, alert engine, notifiers, threat-intel,
                      topology, dashboard (web/)
internal/cli/         endpoints/status/top/alerts/events/audit/… commands
docs/                 operational runbooks (postgres-setup.md)
deploy/               systemd units
```

## Operational gotchas (learned the hard way)

- **The collector runs as a systemd `DynamicUser`** (UID ~63004). It can read
  `Environment=`-injected secrets and its `StateDirectory`, but **cannot read
  root-owned `0600` files**. Pass file-based secrets via systemd `LoadCredential`
  (used for the Gmail SA key) or make them world-readable if public (the PG CA
  cert). Don't expect it to read an arbitrary `/etc/...` `0600` file.
- **Caddy** had `Restart=no` and once stayed down for a day after a crash; it now
  has a `Restart=on-failure` drop-in. If the public site is refused on 80/443 but
  the VM pings, it's almost always Caddy, not `varro-server` (which would give a
  502). Check `systemctl status caddy`.
- **gcloud auth** expires through the day — re-auth with `gcloud auth login`.
- **Fresh-VM `gcloud ssh/scp` often 255s** on a race; retry a few times.
- **Prod changes (push to main, VM deploys, data migrations) are gated** by the
  Claude Code auto-mode classifier and need explicit per-action approval.
- **Scope changes on a VM require stop/start** — doing that to `varro-pg` briefly
  drops Postgres; the collector's pgx pool reconnects and agents disk-buffer.

## Verifying prod quickly

```sh
curl -s https://varro.socfoundry.com/api/v1/health        # version, status, indicator counts
varro endpoints --server https://varro.socfoundry.com --token <personal-api-token>
```

Mint a personal API token for the CLI from the dashboard (Download Agent →
Personal API tokens) — don't reach for the master token.
