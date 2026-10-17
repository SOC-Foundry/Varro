# Install quickstart

Varro is one static Go binary (`varro`) that acts as either the **agent**
(on each monitored endpoint) or the **collector** (the central server). Most
people only install the agent, pointing it at a collector that already exists.

- [Install an agent](#install-an-agent) — put Varro on a machine you want to monitor
- [Run a collector](#run-a-collector) — stand up the server
- [Create orgs & enrollment tokens](#create-orgs--enrollment-tokens)
- [Verify & manage](#verify--manage)
- [Uninstall](#uninstall)

---

## Install an agent

Agents join an **org** using that org's **enrollment token** (the token decides
which org the machine lands in). Get a token from an admin, or mint one yourself
(see [below](#create-orgs--enrollment-tokens)).

### Linux / macOS (one line)

```sh
curl -sSL https://<collector-host>/install.sh | sudo VARRO_TOKEN=<org-enrollment-token> sh
```

The installer downloads the matching binary from the latest signed GitHub
release, **verifies its checksum**, installs a service (systemd on Linux, launchd
on macOS), and the agent enrolls itself and starts reporting. Re-running it
upgrades in place.

### Windows (PowerShell, as Administrator)

```powershell
iwr https://<collector-host>/install.ps1 -UseBasicParsing | iex   # with $env:VARRO_TOKEN set
```

> Tip: the dashboard's **Download agent** view (and **Admin → install**) shows the
> exact per-OS command with your token already filled in — the easiest place to
> copy it from.

After install the agent **auto-upgrades** to the version the collector advertises,
spools samples to disk if the collector is briefly unreachable, and re-enrolls
automatically if its token is lost or revoked. There's nothing else to manage per
host.

What each platform collects differs for the deep sensors — see
[agent-platforms.md](agent-platforms.md).

---

## Run a collector

The collector is the **same binary**, different subcommand. Grab a release binary
from [Releases](https://github.com/SOC-Foundry/Varro/releases) or build from
source (`go build -o varro ./cmd/varro`).

### Quick trial (SQLite, open "lab mode")

```sh
varro server --token <master-secret>
```

No database to set up (pure-Go SQLite) and no sign-in — everything is visible.
Only do this on a trusted network. The dashboard, REST API, and Prometheus
endpoint are served on `:9477`.

### Production (Postgres + Google sign-in behind TLS)

```sh
varro server --token <master-secret> \
  --db-url "postgres://user:pass@host:5432/varro?sslmode=verify-ca" \  # or $VARRO_DB_URL; SQLite if omitted
  --base-url https://varro.example.com \                               # so session cookies are Secure
  --google-client-id   <id>.apps.googleusercontent.com \
  --google-client-secret <secret> \
  --admin-emails you@example.com                                        # first/instance admins
```

- **Storage** — SQLite by default; point `--db-url` at Postgres for scale/HA. The
  schema is auto-migrated and dialect-aware. Migrate an existing SQLite DB with
  `varro migrate-db --to postgres://…`. See [postgres-setup.md](postgres-setup.md)
  and, for high availability, [postgres-ha.md](postgres-ha.md).
- **Auth** — without `--google-client-id` the instance is open (lab mode); with it,
  the dashboard and read API require Google sign-in. The first user to sign in
  (plus anyone in `--admin-emails`) becomes an instance admin.
- **TLS** — terminate at a reverse proxy and set `--base-url https://…`.

Releases publish automatically on a `v*` tag (`.github/workflows/release.yml`), so
agents' auto-upgrade has signed binaries to pull.

---

## Create orgs & enrollment tokens

With the master token (or as an instance admin):

```sh
varro org-create "Acme Corp"
varro org-token  "Acme Corp" --name hq      # agents enroll with this token
varro org-invite "Acme Corp" jane@acme.com  # give a human access (she signs in with Google)
```

Or do all of it in the dashboard under **Admin**. Agents assigned to an org only
appear to members of that org; admins see everything.

---

## Verify & manage

```sh
varro endpoints                 # fleet list (hostname, version, online)
varro status <host>             # latest snapshot
varro top <host>                # live htop-style remote view
varro events                    # fleet security/change feed
varro alerts                    # firing alerts
varro revoke <host>             # cut off a compromised endpoint's token
```

`--server` / `--token` fall back to `$VARRO_SERVER` / `$VARRO_TOKEN`. The web
dashboard at the collector URL shows the same data plus charts, topology, traces,
detections, and response controls. Agent versions and staged rollouts are managed
in **Admin → Fleet**.

---

## Uninstall

**Linux:**
```sh
sudo systemctl disable --now varro-agent
sudo rm -f /etc/systemd/system/varro-agent.service /usr/local/bin/varro
sudo rm -rf /var/lib/varro-agent        # enrollment token + state
```

**macOS:**
```sh
sudo launchctl bootout system /Library/LaunchDaemons/com.socfoundry.varro-agent.plist
sudo rm -f /Library/LaunchDaemons/com.socfoundry.varro-agent.plist /usr/local/bin/varro
```

**Windows (Administrator):** stop/delete the `varro-agent` service and remove the
binary.

Then revoke the endpoint from the dashboard (or `varro revoke <host>`) so its
token can't be reused.
