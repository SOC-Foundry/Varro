# Changelog

All notable changes to Varro. Each entry is a released git tag, newest first;
the format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Dates are commit dates (UTC).

Core agent + collector, alerting, per-agent enrollment tokens, and multi-tenant
orgs predate tagged releases (v0.1–v0.3).

## [v0.67.0] — 2026-10-13
- Synthetic / uptime monitoring: operator-configured active HTTP/TCP probes the collector runs on an interval (not passive agent telemetry). New "📡 Uptime checks" view shows up/down status, latency, and 24h uptime per check, with a probe-latency chart. A down probe raises a `synthetic-down` alert through the existing engine (notifications + SIEM). Probes are SSRF-guarded: each resolved IP is vetted post-DNS (rebinding-safe) — link-local/cloud-metadata blocked for all orgs, loopback/private only for Infrastructure orgs. `GET/POST/DELETE /api/v1/synthetic`.
- Fix: server-generated alert rules (`service-error-rate`, `service-latency-p95`, `log-error-burst`, and the new `synthetic-down`) are now exempt from orphaned-alert cleanup, which previously flapped them resolved→firing every 15s.

## [v0.66.0] — 2026-10-12
- Postgres HA: a hot streaming standby (`varro-pg-2`) replicates the primary (async, ~2ms lag), pre-staged with a CA-signed cert + listening on its IP so failover is promote + repoint. Removes the last single point of failure. Runbook: docs/postgres-ha.md. (Infra + docs; no agent change.)

## [v0.65.0] — 2026-10-12
- Deploy→regression correlation: when a CI/CD deploy is followed by a service error-rate or p95-latency regression, Varro raises a `deploy_regression` event + alert ("this deploy likely caused this").

## [v0.64.0] — 2026-10-11
- Alerting on telemetry: service SLO alerts (error rate, p95 latency from traces) and per-endpoint log-error-burst alerts, alongside the existing host-metric alerts.

## [v0.63.0] — 2026-10-11
- Service health (RED) from traces: per-service request rate, error rate, and p50/p95/p99 latency (`GET /api/v1/otlp/services`), shown atop the Traces view.

## [v0.62.0] — 2026-10-11
- Flows map: CDN/anycast destinations (whose IP geo is meaningless) are grouped into a dedicated "CDN / anycast" cluster instead of a bogus country; the table shows "CDN · <ASN>".

## [v0.61.0] — 2026-10-11
- Flows map: destination dots are now draggable (like the topology canvas) so same-country clusters can be spread out; positions persist across refreshes.

## [v0.60.0] — 2026-10-11
- CI/CD webhook ingest (`POST /api/v1/cicd`): pipeline build/deploy events become first-class events and overlay as deploy markers on metric charts for deploy↔metric correlation.

## [v0.59.0] — 2026-10-11
- OTLP logs ingest (`POST /v1/logs`): app logs pushed via OpenTelemetry land in the existing Logs view alongside journald. Completes OTLP metrics + traces + logs.

## [v0.58.0] — 2026-10-11
- OTLP traces ingest (`POST /v1/traces`) with a Traces view + per-trace span waterfall. Plus a fix: OTLP metric values now store at double precision (Postgres REAL was single-precision, losing precision on large counters).

## [v0.57.0] — 2026-10-11
- OTLP/HTTP metrics ingest: apps push custom app/API metrics via OpenTelemetry to `POST /v1/metrics` (JSON), viewable in a new Custom metrics view. Varro's first application/API telemetry path.

## [v0.56.0] — 2026-10-11
- Metric explorer: compare any metric (CPU, memory, disk, network, I/O, temp) across multiple hosts over a time range (`GET /api/v1/metrics/series`), plus named saved views (per user).

## [v0.55.1] — 2026-10-11
- Fix: flow byte volumes now populate on hosts without the nf_conntrack module (v0.55.0 returned early there, skipping the tcp_info overlay).

## [v0.55.0] — 2026-10-11
- Flow byte volumes via tcp_info (sock_diag / `ss`), so the Flows map/table show real transfer sizes without conntrack or host config (the collector has no nf_conntrack module). Plus a flows-map label polish (labels try multiple sides so small destinations still get named).

## [v0.54.0] — 2026-10-11
- Runtime-reachability vulnerability prioritization: a "Priority fixes" view (and `GET /api/v1/vuln-priority`) ranks vulnerable hosts by exposure (internet-facing, talks-to-malicious, online) × severity, not raw CVSS — "what to patch first." Plus a Flows-map fix: same-country destinations fan out on a ring instead of stacking into unreadable labels.

## [v0.53.1] — 2026-10-11
- Fix Flows map/table geo always empty: read the destination geo from the topology node (where buildTopology stores it) instead of the edge, which never carried it.

## [v0.53.0] — 2026-10-11
- Logs pillar: agents ship journald logs (cursor-based, `--capture-logs`); a new Logs view searches, filters (host/severity/text/time), and live-tails them over `GET /api/v1/logs`. Adds the third telemetry pillar alongside metrics and events.

## [v0.52.0] — 2026-10-11
- Flows & talkers view: top external talkers (bytes, connections, source hosts, geo) over `GET /api/v1/flows`, plus an animated world map plotting destinations by country, sized by conntrack byte volume. Surfaces flow data already collected but previously hidden.

## [v0.51.0] — 2026-10-11
- No code change from v0.50.0; cut from the same commit to validate the pinned, flap-free deploy flow end to end.

## [v0.50.0] — 2026-10-11
- Pin agent desired-version via `VARRO_AGENT_DESIRED_VERSION` env so rolling binary deploys no longer flap agents across the load balancer.

## [v0.49.0] — 2026-10-10
- Org `infrastructure` flag (`varro org-infra`): flagged orgs are excluded from the "all orgs" compliance aggregate so monitoring infra doesn't skew tenant numbers.

## [v0.48.0] — 2026-10-10
- Bucket vulnerability severities by CVSS score (exact v3.x, v2.0, approximate v4.0) instead of grouping by raw CVSS vector strings.

## [v0.47.0] — 2026-10-10
- Reassign an endpoint to another org (`varro endpoint-move-org`), updating the token→org binding so the move survives the next snapshot.

## [v0.46.1] — 2026-10-10
- Fix the compliance report view flashing closed when the periodic endpoint refresh ran.

## [v0.46.0] — 2026-10-10
- Compliance report: per-org rollup of CIS-lite posture (scored), vulns by severity, and patch/service health, with CSV export and print-to-PDF.

## [v0.45.0] — 2026-10-10
- Filter loopback destinations in all connection-based detection rules, not just the eBPF rule.

## [v0.44.0] — 2026-10-10
- Fix loopback false positives, dedupe critical-node reasons, and time-bound the risk window.

## [v0.43.0] — 2026-10-10
- Make critical-node reason lines in the topology clickable through to the endpoint.

## [v0.42.0] — 2026-10-10
- Topology: critical nodes surface *why* they're critical (the actual triggering events).

## [v0.41.0] — 2026-10-10
- eBPF connect sensor: capture short-lived outbound connections with process attribution.

## [v0.40.0] — 2026-10-10
- Topology: group boxes off by default plus a group-cohesion layout force.

## [v0.39.0] — 2026-10-10
- Topology: time-travel playback and scale clustering (group hulls + collapse).

## [v0.38.0] — 2026-10-10
- Topology: website/service external nodes plus attack-path blast-radius.

## [v0.37.0] — 2026-10-10
- Detection: SIEM export (JSON POST) and cross-endpoint indicator correlation.

## [v0.36.0] — 2026-10-10
- Detection: MITRE ATT&CK technique mapping on behavioral detections.

## [v0.35.0] — 2026-10-10
- Scale: leader election for HA-safe operation with multiple collectors.

## [v0.34.0] — 2026-10-10
- Scale: tiered retention, prune index, and Postgres connection recycling.

## [v0.33.0] — 2026-10-10
- Alert incident lifecycle: acknowledge / assign / resolve-with-note.

## [v0.32.0] — 2026-10-09
- Postgres: BIGINT for INTEGER columns and a SQLite→Postgres data migration tool.

## [v0.31.0] — 2026-10-09
- Topology: website visibility via passive DNS/SNI plus domain intelligence.

## [v0.30.0] — 2026-10-09
- Per-token revoke for enrollment tokens.

## [v0.29.0] — 2026-10-09
- Personal API tokens for CLI/API access.

## [v0.28.0] — 2026-10-04
- Host isolation for macOS (pf) and Windows (netsh).

## [v0.27.0] — 2026-10-04
- Upgrade the topology view into a risk map.

## [v0.26.1] — 2026-10-04
- Fix stored XSS via attacker-controlled names in action-button handlers.

## [v0.26.0] — 2026-10-04
- Off-VM database backups to GCS.

## [v0.25.0] — 2026-10-04
- Behavioral detection engine.

## [v0.24.0] — 2026-10-04
- eBPF exec sensor for kernel-level, no-gap process capture.

## [v0.23.0] — 2026-10-04
- Continuous byte-counted network flows via conntrack.

## [v0.22.0] — 2026-10-04
- Workload-centric telemetry: containers and cloud context.

## [v0.21.0] — 2026-10-04
- Postgres backend alongside SQLite.

## [v0.20.1] — 2026-10-04
- Let any signed-in user download the agent.

## [v0.20.0] — 2026-10-04
- Hash-based threat matching.

## [v0.19.0] — 2026-10-04
- Threat-intel enrichment.

## [v0.18.0] — 2026-10-04
- Admin audit log and resizable vulnerability columns.

## [v0.17.1] — 2026-10-04
- Reverse-DNS enrichment, iptables isolation fallback, installer restart handling.

## [v0.17.0] — 2026-10-04
- Response actions: kill process and network isolation.

## [v0.16.1] — 2026-10-04
- Drain the vuln details queue after each scan instead of hourly batches.

## [v0.16.0] — 2026-10-04
- Vulnerability matching against OSV.dev.

## [v0.15.1] — 2026-10-04
- Scale topology edge thickness and arrow size with connection volume.

## [v0.15.0] — 2026-10-04
- Interactive topology graph with animated flow.

## [v0.14.3] — 2026-10-04
- Fix topology view being kicked back to the endpoint dashboard.

## [v0.14.2] — 2026-10-04
- Fix dashboard tab crashes from per-frame canvas reallocation.

## [v0.14.1] — 2026-10-04
- Normalize topology edge direction via the listening-port index.

## [v0.14.0] — 2026-10-04
- Fleet topology map.

## [v0.13.1] — 2026-10-04
- Mobile-friendly dashboard.

## [v0.13.0] — 2026-10-03
- Posture checks, patch/health status, and file integrity monitoring.

## [v0.12.1] — 2026-10-03
- Member role toggles in the admin panel and a last-org-admin guard.

## [v0.12.0] — 2026-10-03
- Org admins get endpoint lifecycle control within their org.

## [v0.11.3] — 2026-10-03
- Remember the dashboard's selected org scope across page loads.

## [v0.11.2] — 2026-10-03
- `user-admin` command to grant/revoke instance-admin status.

## [v0.11.1] — 2026-10-03
- Gmail API (service-account delegation) mail transport and health endpoint.

## [v0.11.0] — 2026-10-03
- Cloudflare Email Service backend for outbound mail.

## [v0.10.1] — 2026-10-03
- `org-delete` command and API for decommissioning empty orgs.

## [v0.10.0] — 2026-10-03
- Automated user onboarding: domain auto-join, invite emails, `varro onboard`.

## [v0.9.0] — 2026-10-03
- macOS agent support.

## [v0.8.0] — 2026-10-03
- Dashboard admin panel, org-admin role, and in-app agent installs.

## [v0.7.1] — 2026-10-03
- Fix Windows installer to use `New-Service` instead of `sc.exe create`.

## [v0.7.0] — 2026-10-03
- Windows agent support.

## [v0.6.0] — 2026-10-03
- Hardware, security-depth, and inventory telemetry.

## [v0.5.0] — 2026-10-03
- Stabilize agent identity and sign releases.

## [v0.4.2] — 2026-10-03
- Agent auto-upgrade from GitHub releases.

## [v0.4.1] — 2026-10-03
- `endpoint-remove` and `org-remove-member` admin commands.

## [v0.4.0] — 2026-10-02
- One-line agent installer and release automation.
