# Postgres backend — setup runbook

How the production collector runs against Postgres: a dedicated VM, TLS-encrypted
link, SQLite→Postgres data migration, and daily GCS backups. This captures steps
that otherwise live only on the VMs, so the setup is reproducible after a rebuild.

Varro itself is datastore-agnostic: `store.Open` picks Postgres when the DSN
starts with `postgres://`/`postgresql://`, else SQLite. Enable Postgres with
`--db-url` or `VARRO_DB_URL`.

## Topology (as deployed)

| Host | Role | Internal IP |
|------|------|-------------|
| `varro-collector` (e2-micro) | collector + Caddy + self-agent, runs as systemd `DynamicUser` | `10.128.0.2` |
| `varro-pg` (e2-small, debian-12) | PostgreSQL 15 | `10.128.0.10` |

Both in project `varro-510502`, zone `us-central1-a`, default VPC (so
`default-allow-internal` permits collector→pg traffic). Postgres is **not**
exposed publicly — it listens only on localhost + its internal IP, and `pg_hba`
admits only the collector's IP over TLS.

Backups bucket: `gs://varro-backups-510502` (30-day delete lifecycle).

---

## 1. Provision the Postgres VM

```bash
PROJ=varro-510502 ZONE=us-central1-a
gcloud compute instances create varro-pg \
  --project $PROJ --zone $ZONE \
  --machine-type e2-small \
  --image-family debian-12 --image-project debian-cloud \
  --boot-disk-size 20GB
```

The VM needs **storage read-write** scope to upload backups (default is
read-only). This requires a stop/start — a brief Postgres outage; the collector
(pgx pool) reconnects automatically and agents disk-buffer meanwhile:

```bash
gcloud compute instances stop varro-pg --project $PROJ --zone $ZONE
gcloud compute instances set-service-account varro-pg --project $PROJ --zone $ZONE \
  --service-account=998169443176-compute@developer.gserviceaccount.com \
  --scopes=storage-rw,logging-write,monitoring-write
gcloud compute instances start varro-pg --project $PROJ --zone $ZONE
```

(`set-service-account --scopes` is the GA command; `set-scopes` is beta-only.)

## 2. Install and configure PostgreSQL

On `varro-pg`:

```bash
sudo apt-get update && sudo apt-get install -y postgresql
PG_IP=10.128.0.10 COLLECTOR_IP=10.128.0.2
CONF=/etc/postgresql/15/main

# Listen on localhost + the internal IP only (never the public interface).
sudo sed -i "s/^#\?listen_addresses.*/listen_addresses = 'localhost,$PG_IP'/" $CONF/postgresql.conf

# Role + database (use a strong, unique password).
sudo -u postgres psql -c "CREATE ROLE varro LOGIN PASSWORD '<PGPASS>'"
sudo -u postgres psql -c "CREATE DATABASE varro OWNER varro"
```

The Varro schema is created automatically on first connect (`store.migrate()`);
no manual DDL.

## 3. TLS on the collector↔Postgres link

Encrypt and authenticate the link with a private CA. `verify-ca` prevents both
eavesdropping and MITM (an attacker can't present a cert signed by our CA)
without the IP-hostname-matching fragility of `verify-full` (the SAN below makes
`verify-full` possible later if wanted).

On `varro-pg`:

```bash
CONF=/etc/postgresql/15/main
cd /tmp
# Private CA.
openssl req -new -x509 -days 3650 -nodes -newkey rsa:2048 \
  -keyout ca.key -out ca.crt -subj "/CN=Varro-PG-CA"
# Server cert, signed by the CA; SAN carries the internal IP.
openssl req -new -nodes -newkey rsa:2048 -keyout server.key -out server.csr \
  -subj "/CN=varro-pg" -addext "subjectAltName=IP:10.128.0.10,DNS:varro-pg"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 3650 -out server.crt -copy_extensions copyall

sudo install -o postgres -g postgres -m 600 server.key $CONF/server.key
sudo install -o postgres -g postgres -m 644 server.crt $CONF/server.crt
sudo install -o root    -g root    -m 600 ca.key      $CONF/ca.key   # keep to re-issue

sudo sed -i "s|^#*\s*ssl\s*=.*|ssl = on|"                                   $CONF/postgresql.conf
sudo sed -i "s|^#*\s*ssl_cert_file\s*=.*|ssl_cert_file = '$CONF/server.crt'|" $CONF/postgresql.conf
sudo sed -i "s|^#*\s*ssl_key_file\s*=.*|ssl_key_file = '$CONF/server.key'|"   $CONF/postgresql.conf

# Admit ONLY the collector, ONLY over TLS.
echo "hostssl varro varro 10.128.0.2/32 scram-sha-256 # varro-collector-access" \
  | sudo tee -a $CONF/pg_hba.conf
sudo systemctl restart postgresql

# Copy ca.crt to the collector (public cert — safe to read widely).
cp /tmp/ca.crt /tmp/pg-ca.crt   # then scp to the collector, see step 5
```

## 4. Migrate existing SQLite data (one-time cutover)

Build the collector/CLI binary (contains `migrate-db`), then on `varro-collector`:

```bash
# 1. Quiesce the source so the copy is consistent.
sudo systemctl stop varro-server

# 2. (optional, re-runnable) start from an empty destination.
#    migrate-db truncates the destination itself, but a fresh db is cleanest:
#    on varro-pg:  sudo -u postgres psql -c 'DROP DATABASE varro'; psql -c 'CREATE DATABASE varro OWNER varro'

# 3. Copy every table SQLite -> Postgres (pass the DSN via env to keep the
#    password out of the process list). Verifies per-table row counts.
sudo VARRO_DB_URL='postgres://varro:<PGPASS>@10.128.0.10:5432/varro?sslmode=verify-ca&sslrootcert=/etc/varro/pg-ca.crt' \
  varro migrate-db --from /var/lib/varro/varro.db
```

`migrate-db` streams tables in batches, loads FK parents (`orgs`, `users`)
first, resets `BIGSERIAL` sequences, and fails if any table's source/destination
row counts differ.

Keep the SQLite file as a rollback: `sudo cp /var/lib/varro/varro.db
/var/lib/varro/varro.db.sqlite-backup`.

## 5. Point the collector at Postgres

On `varro-collector`. The server runs as a systemd `DynamicUser`, so:

- the **CA cert must be world-readable** (`0644`) — it's public, so this is fine
  and avoids a `LoadCredential` dance;
- the **DSN is passed via `Environment=`** (systemd injects it regardless of the
  runtime user) in a **root-only (`0600`) drop-in** since it contains the
  password.

```bash
sudo install -o root -g root -m 644 /tmp/pg-ca.crt /etc/varro/pg-ca.crt

sudo mkdir -p /etc/systemd/system/varro-server.service.d
printf '[Service]\nEnvironment=VARRO_DB_URL=%s\n' \
  'postgres://varro:<PGPASS>@10.128.0.10:5432/varro?sslmode=verify-ca&sslrootcert=/etc/varro/pg-ca.crt' \
  | sudo tee /etc/systemd/system/varro-server.service.d/postgres.conf
sudo chmod 600 /etc/systemd/system/varro-server.service.d/postgres.conf

sudo systemctl daemon-reload
sudo systemctl restart varro-server
```

`VARRO_DB_URL` overrides the unit's `--db` SQLite flag, so no ExecStart edit is
needed.

### Verify

```bash
# On varro-pg: all collector connections should be ssl=t, TLSv1.3.
sudo -u postgres psql -d varro -tAc \
  "SELECT host(a.client_addr), s.ssl, s.version FROM pg_stat_ssl s
   JOIN pg_stat_activity a ON s.pid=a.pid WHERE a.usename='varro'"

# From the collector: plaintext must be REJECTED, verified SSL must SUCCEED.
PGPASSWORD=<PGPASS> psql 'host=10.128.0.10 dbname=varro user=varro sslmode=disable' -c 'SELECT 1'
#   -> FATAL: no pg_hba.conf entry ... no encryption
PGPASSWORD=<PGPASS> psql 'host=10.128.0.10 dbname=varro user=varro sslmode=verify-ca sslrootcert=/etc/varro/pg-ca.crt' -c 'SELECT 1'
#   -> 1
```

### Rollback to SQLite

```bash
sudo rm /etc/systemd/system/varro-server.service.d/postgres.conf
sudo systemctl daemon-reload && sudo systemctl restart varro-server   # back on --db SQLite
```

## 6. Daily backups to GCS

`varro-pg` runs a timer that `pg_dump | gzip`s the DB and uploads it to GCS,
authenticated by the VM's metadata service-account token (no key files),
mirroring the collector's SQLite backups. The bucket's 30-day lifecycle rotates
old dumps.

`/usr/local/bin/varro-pg-backup.sh`:

```bash
#!/bin/bash
set -euo pipefail
BUCKET=varro-backups-510502
PREFIX=postgres
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$(mktemp /tmp/varro-pg-XXXXXX.sql.gz)
trap 'rm -f "$OUT"' EXIT

sudo -u postgres pg_dump varro | gzip > "$OUT"

TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  | grep -o '"access_token":"[^"]*"' | sed 's/.*:"//;s/"$//')
[ -n "$TOKEN" ] || { echo "no metadata token" >&2; exit 1; }

curl -sf -X POST --data-binary @"$OUT" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/gzip" \
  "https://storage.googleapis.com/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=${PREFIX}%2Fvarro-${TS}.sql.gz" >/dev/null
echo "uploaded gs://${BUCKET}/${PREFIX}/varro-${TS}.sql.gz"
```

systemd units (`varro-pg-backup.service` oneshot + `varro-pg-backup.timer`
`OnCalendar=*-*-* 03:30:00`, `Persistent=true`):

```bash
sudo install -m 755 varro-pg-backup.sh /usr/local/bin/varro-pg-backup.sh
sudo systemctl enable --now varro-pg-backup.timer
sudo systemctl start varro-pg-backup.service   # test run
```

### Restore (verified via drill)

```bash
# Download an object, then load it. Use a throwaway db to drill without risk.
gunzip -c varro-<ts>.sql.gz | sudo -u postgres psql <target-db>
```

A restore drill (restore into a scratch db, compare durable-table counts to
live, drop the scratch db) confirmed the backups round-trip cleanly.

## Notes / gotchas

- **SQLite `INTEGER` is 64-bit** → the Postgres dialect maps `INTEGER`→`BIGINT`
  (and `INTEGER PRIMARY KEY`→`BIGSERIAL`). A column like `mem_total` overflows
  `int4` on hosts with >2 GB RAM; this only surfaced during a real migration.
- **Scope change needs a stop/start**, which briefly drops Postgres — do it
  during a maintenance window; the collector reconnects and agents buffer.
- `pg_dump` output is a small gzip (~20 MB vs ~370 MB raw SQLite) — it's logical
  and dominated by 72h-retention telemetry; durable config is a tiny fraction.
