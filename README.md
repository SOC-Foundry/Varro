# Varro

Endpoint telemetry with teeth: a lightweight Go agent that scans hardware, OS,
and security-relevant state (CPU, memory, disks, network, processes, listening
ports, sessions, persistence locations) on each endpoint and ships it to a
central collector with alerting, anomaly detection, a live web dashboard, REST
API, Prometheus exporter, and CLI.

Everything is a single static binary — `varro` — with subcommands.

## Architecture

```
endpoint A ──┐                             ┌─ alert engine ──▶ webhook / Slack / email
endpoint B ──┼─ varro agent ──HTTP/JSON──▶ varro server ──▶ SQLite history
endpoint C ──┘  (per-agent tokens,             │
                 disk spool, gopsutil)         ├─ web dashboard   /
                                               ├─ REST API        /api/v1/...
                                               └─ Prometheus      /metrics
```

**Agent** (default every 10s, server-configurable):
- Hardware/OS: per-core CPU + load, memory/swap, per-filesystem disk, per-NIC
  network counters with computed byte rates, top 30 processes by CPU.
- Security: listening sockets (with owning process), established-connection
  count, logged-in sessions, failed-auth counts from the auth log (best
  effort), and change **events** — new process, new listening port, new NIC,
  new user session, autostart/cron/systemd persistence changes.
- Resilience: enrolls once for a **per-agent token** (stored in
  `--state-dir`, default `~/.local/state/varro`); samples that can't be
  shipped are **spooled to disk** and delivered after reconnect or restart; a
  revoked/lost token self-heals by re-enrolling.

**Server**:
- Ingest (per-agent token auth), SQLite history (pure Go, no cgo), retention
  pruning (default 72h).
- **Alert engine**: threshold rules with sustain windows (defaults: CPU>90%
  5m, mem>95% 5m, swap>80% 5m, disk>85%, offline 90s — or your own
  `--rules rules.json`), plus **z-score anomaly detection** against each
  endpoint's own 7-day baseline (CPU and network rates; fire >3σ, resolve <2σ).
- Notifications on fire/resolve via generic **webhook**, **Slack** webhook,
  and **SMTP email**; selected security events (default: autostart changes,
  new NICs, new listeners) are forwarded as they arrive.

## Quick start

```sh
go build -o varro ./cmd/varro

# 1. Collector
./varro server --token s3cret \
    --slack-webhook-url https://hooks.slack.com/services/…   # optional

# 2. Agent on each endpoint (enrolls itself, then uses its own token)
./varro agent --server http://collector-host:9477 --token s3cret

# 3. Consume
open http://collector-host:9477        # dashboard: charts, security, events, alerts
./varro endpoints                      # fleet list (incl. agent version)
./varro status myhost                  # latest snapshot
./varro top myhost                     # live htop-style remote view
./varro alerts                         # firing alerts (--all for history)
./varro events                         # fleet security/change feed
./varro revoke myhost --token s3cret   # cut off a compromised endpoint
curl http://collector-host:9477/metrics   # Prometheus scrape target
```

`--server`/`--token` fall back to `$VARRO_SERVER`/`$VARRO_TOKEN`.

## Multi-tenancy (orgs) and Google sign-in

Varro is multi-tenant: endpoints, events, and alerts belong to an **org**, and
users only see the orgs they're members of. Agents are assigned to an org by
the enrollment token they join with; humans sign in with Google.

```sh
# Admin (master token) sets up a tenant:
varro org-create "Acme Corp"            --token $MASTER
varro org-token  "Acme Corp" --name hq  --token $MASTER   # agents enroll with this
varro org-invite "Acme Corp" jane@acme.com --token $MASTER

# Acme's agents:
varro agent --server https://varro.example.com --token <acme-enrollment-token>
```

Without `--google-client-id` the server runs **open (lab mode)** — no sign-in,
everything visible — which is what you get out of the box. To require sign-in:

1. In the [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
   (project `varro-510502`): **APIs & Services → Credentials → Create
   Credentials → OAuth client ID**, type **Web application**.
   - Authorized redirect URI: `https://<your-base-url>/auth/callback`
     (for local testing: `http://localhost:9477/auth/callback`)
   - Configure the OAuth consent screen if prompted (External, scopes:
     `openid`, `email`, `profile`).
2. Start the server with the credentials:

```sh
varro server --token $MASTER \
  --base-url https://varro.example.com \
  --google-client-id  1234-abc.apps.googleusercontent.com \
  --google-client-secret $SECRET \
  --admin-emails david@socfoundry.com
```

The **first user ever to sign in becomes an instance admin**, as does anyone
in `--admin-emails`. Admins see all orgs (with an "All orgs" switcher in the
dashboard) and can manage orgs; everyone else sees only orgs they've been
invited to. The CLI authenticates with `--token` (master token = admin; an
org's enrollment token = read-only for that org). `/metrics` stays open unless
`--metrics-token` is set.

## Alert rules file

`--rules rules.json` replaces the built-ins. Metrics: `cpu_pct`, `mem_pct`,
`disk_pct`, `swap_pct`, `rx_rate`, `tx_rate`, or `offline`.

```json
[
  {"name": "high-cpu",  "metric": "cpu_pct", "op": ">", "threshold": 90, "for_seconds": 300},
  {"name": "offline",   "metric": "offline", "for_seconds": 90}
]
```

Alerts fire when the metric's average over the trailing `for_seconds` window
breaches the threshold, and auto-resolve when it recovers (rules removed from
the file have their open alerts resolved on restart).

## HTTP API

Read endpoints take an optional `?org=` to narrow scope. "read auth" below
means: session cookie, org enrollment token, or master token — unless the
server runs in open (lab) mode, where reads are unauthenticated.

| Method | Path                               | Auth           | Description                       |
|--------|------------------------------------|----------------|-----------------------------------|
| POST   | `/api/v1/enroll`                   | org/master tok | Issue a per-agent token           |
| POST   | `/api/v1/ingest`                   | agent token    | Batch snapshot upload             |
| GET    | `/api/v1/agent/config`             | agent token    | Server-pushed agent settings      |
| DELETE | `/api/v1/endpoints/{id}/token`     | master token   | Revoke an agent's token           |
| GET    | `/api/v1/me`                       | session        | Current user + visible orgs       |
| GET/POST | `/api/v1/orgs`                   | admin          | List / create orgs                |
| POST   | `/api/v1/orgs/{id}/tokens`         | admin          | Mint org enrollment token         |
| POST   | `/api/v1/orgs/{id}/members`        | admin          | Invite a user by email            |
| GET    | `/auth/login`, `/auth/callback`    | —              | Google sign-in flow               |
| GET    | `/api/v1/endpoints`                | read auth      | Fleet list + headline metrics     |
| GET    | `/api/v1/endpoints/{id}/latest`    | read auth      | Latest full snapshot              |
| GET    | `/api/v1/endpoints/{id}/history`   | read auth      | Time series (`?minutes=`, ≤7d)    |
| GET    | `/api/v1/endpoints/{id}/events`    | read auth      | Endpoint event feed (`?limit=`)   |
| GET    | `/api/v1/events`                   | read auth      | Fleet event feed                  |
| GET    | `/api/v1/alerts`                   | read auth      | Alerts (`?state=firing`)          |
| GET    | `/metrics`                         | metrics token* | Prometheus text (*if configured)  |
| GET    | `/`                                | —              | Web dashboard (login screen)      |

## Security notes

- Ingest requires a per-agent token (SHA-256 hashes at rest; revocable per
  endpoint), and an agent can only report as the ID it enrolled with. Org
  enrollment tokens only grant joining that org — don't bake the master token
  into agent images. Re-enrollment of an existing agent ID is refused unless
  the server runs with `--allow-reenroll`.
- The master token is still accepted for ingest ("lab mode") so you can demo
  without enrollment; rely on per-agent tokens for anything real.
- With Google sign-in configured, the dashboard and read API require a
  session (or a token); without it the instance is **open** — only run open
  mode on trusted networks. Transport is plain HTTP; terminate TLS at a
  reverse proxy and set `--base-url https://...` so cookies are marked Secure.
- Failed-auth counting reads `/var/log/auth.log` or `/var/log/secure` and
  needs an agent with permission to do so; it reports 0 otherwise.

## Layout

```
cmd/varro/           entry point, flag wiring, version stamp
internal/model/      shared types (snapshots, events, alerts, rules)
internal/collect/    gopsutil collectors + security collectors/event diffs
internal/agent/      sample loop, enrollment, disk spool, pushed config
internal/store/      SQLite persistence, baselines, tokens, retention
internal/server/     ingest/query API, alert engine, notifiers, dashboard
internal/server/web/ self-contained dashboard (no external assets)
internal/cli/        endpoints/status/top/alerts/events/revoke commands
deploy/              systemd units for agent and server
```

## Cross-compiling agents

Pure Go all the way down:

```sh
make cross   # linux amd64/arm64, darwin arm64, windows amd64 into dist/
```

Linux agents report the most (sessions, auth failures, autostart watching);
macOS/Windows agents degrade gracefully to whatever gopsutil exposes there.
