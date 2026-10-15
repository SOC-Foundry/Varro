# Changelog

All notable changes to Varro. Each entry is a released git tag, newest first;
the format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Dates are commit dates (UTC).

Core agent + collector, alerting, per-agent enrollment tokens, and multi-tenant
orgs predate tagged releases (v0.1–v0.3).

## [v0.89.0] — 2026-10-14
- Traces view: added a "Send traces here" quickstart card with the copy-paste OTLP exporter env vars (endpoint, http/json protocol, bearer header, service name) and a note on trace-context propagation — so the setup for the service dependency map lives right where you'd look for it. Mirrors the existing hint in the Custom metrics view.

## [v0.88.0] — 2026-10-14
- Fix (navigation): added a persistent **Endpoints** tab at the top of the sidebar's Explore nav that returns to the main device dashboard from any view. Previously the only way back was the small "← back to endpoints" link inside each view (or clicking a device in the sidebar, which is hidden on mobile after the sidebar closes) — so after switching between Explore tabs there was no obvious way home. The Endpoints tab highlights as active whenever no Explore view is open.

## [v0.87.0] — 2026-10-14
- STIX/TAXII threat-intel ingest + IOC management: orgs can now maintain their own indicators of compromise (IPs, domains, SHA-256 hashes) alongside the built-in abuse.ch feeds. Add them by hand, poll a STIX 2.1 / TAXII 2.1 feed URL on a schedule, or paste a STIX bundle to import. Ingested indicators are matched against endpoint connections, resolved domains, and process-binary hashes with the same rate-limited alerting/SIEM/correlation path as the global feeds. New "Threat intelligence" card in the Admin view (IOC table + per-type counts, feed management with last-poll status, bundle import). Feed fetches are SSRF-guarded (link-local/metadata/private/CGNAT blocked for non-infra orgs, same policy as webhooks/synthetic probes). STIX patterns parsed: `ipv4/ipv6-addr:value`, `domain-name:value`, `url:value` (host extracted), `file:hashes.'SHA-256'`; raw SCOs handled too. `GET/POST/DELETE /api/v1/orgs/{id}/iocs`, `GET/POST/DELETE /api/v1/orgs/{id}/stix/feeds`, `POST …/stix/feeds/{fid}/refresh`, `POST …/stix/ingest` (all org-admin). Per-org overlay is matched on every collector and reloaded cluster-wide after an ingest; feed polling is leader-gated.

## [v0.86.0] — 2026-10-13
- Service dependency map (Traces view): a caller→callee graph derived from span parentage — whenever a span's parent runs in a different `service.name`, that's a call from the parent's service to the child's service. Edges show call counts, error rate (color), and p50/p95 latency on hover; nodes show incoming/outgoing call totals, mark entrypoint (root-span) services, and highlight services serving a high error rate. Laid out in columns by distance from an entrypoint. `GET /api/v1/otlp/graph?minutes=` (read-scoped, org-filtered); metrics measured on the callee (downstream) span.

## [v0.85.0] — 2026-10-14
- CI now runs the suite on real Windows + macOS runners, validating the previously cross-compile-only agent code: the Windows Event Log and macOS unified-log collectors execute on-OS (baseline + incremental), and the ETW session is exercised on `windows-latest`.
- Windows ETW process-start sensor is now **default-on** (was opt-in in v0.84.0): the ETW session is CI-validated to open/run/close on a real Windows runner without the syscall-boundary crash I'd flagged, so the `VARRO_ETW` gate is removed. It stays defensive — any `Start()` failure (e.g. a non-admin host) falls back to the polling sensor, and the event callback is panic-contained. (Event-field parsing remains best-effort; a TDH-based decode is a documented follow-up.)

## [v0.84.0] — 2026-10-13
- Windows ETW process-start sensor (experimental, opt-in): `internal/etw` adds a real-time consumer of the Kernel-Process provider for short-lived process capture the polling sensor misses — the Windows analog of the Linux eBPF exec sensor. The agent tries ETW before the polling sensor, but **only when `VARRO_ETW=1` is set.** It's deliberately not default-on: it's hand-rolled ETW syscall code (x/sys/windows ships no ETW types) that hasn't run on a real Windows host, and a struct-layout bug there faults at the syscall (an uncatchable crash, not a graceful error). It's panic-contained and fails over to the polling sensor on any setup error; flip it to default-on after validating on Windows. See docs/agent-platforms.md.

## [v0.83.0] — 2026-10-13
- Cross-platform log collection: the logs pillar now works beyond Linux journald — Windows agents collect the Event Log (System + Application, via `Get-WinEvent`) and macOS agents the unified log (via `log show --style ndjson`), both incremental by a cursor and feeding the same Logs view + log-based detections/hunts. Best-effort: cross-compiled and graceful-degrading (any failure disables capture rather than crashing, i.e. no worse than the previous "no logs"); field validation on real Windows/macOS hosts is a follow-up. See docs/agent-platforms.md.

## [v0.82.0] — 2026-10-13
- Incident notifications: a newly-opened incident (or one escalating to CRITICAL) now notifies via the org's routes + the global webhook/Slack/email — incidents previously formed silently. Because incidents group related signals, this pages far less than per-alert notifications did.
- Scheduled report digests: a per-org recurring email digest (daily or weekly) summarizing fleet posture, vulnerabilities, patching, and open/critical incidents. Configured in Admin → Scheduled report digest. `GET/PUT /api/v1/orgs/{id}/report-schedule`; a leader-only hourly scheduler sends due digests via the existing mail transport.

## [v0.81.0] — 2026-10-13
- Fix (Flows & talkers map): dragging destination dots now works — the animation loop was recomputing its change-signature with a different formula than the layout stored, so it rebuilt (and replaced) the dots every frame, discarding the one being dragged so it snapped back. Also, same-zone destinations are now fanned out on a sunflower/phyllotaxis layout instead of piling onto a single ring, so dense clusters (e.g. many US destinations) are readable without dragging.

## [v0.80.0] — 2026-10-13
- Cross-platform process-start sensing: Windows and macOS agents (and old/unprivileged Linux) now feed process-start events to the detection engine via a portable polling sensor that diffs the process table each sample — previously only Linux (eBPF) populated this, so custom/built-in detection rules on the process stream now work on every platform. (Most detections already worked cross-platform via gopsutil processes/connections/ports; this adds the process-start signal.) The polling sensor can't catch sub-interval processes the way the Linux eBPF sensor does; true kernel-native deep sensors — Windows ETW, macOS Endpoint Security Framework — remain a documented roadmap item (macOS ESF needs Apple-signed system-extension packaging). See docs/agent-platforms.md.

## [v0.79.0] — 2026-10-13
- Incident management: related alerts and detections for the same endpoint now auto-group into an incident (2-hour correlation window) with a rolled-up severity, a timeline, a status (open → acknowledged → resolved), and an assignee. A new "🚨 Incidents" view triages them — ack, assign, resolve, add notes — with the full timeline of every signal and action. API: `GET /api/v1/incidents` + `/{id}` and `POST /{id}/ack|assign|resolve|note`.

## [v0.78.0] — 2026-10-13
- Security hardening (from a focused review of the v0.67–v0.77 surface; no high-severity issues found): the synthetic-probe / webhook SSRF guard now also blocks CGNAT (`100.64.0.0/10`) and reserved ranges (`192.0.0.0/24`, `198.18.0.0/15`, `240.0.0.0/4`) for non-infrastructure orgs — `net.IP.IsPrivate()` missed these. And webhook/Slack delivery-failure logs now redact the URL to scheme+host so path-embedded secrets never reach the logs.

## [v0.77.0] — 2026-10-13
- Retention rollups: raw samples (kept ~72h) are folded into hourly per-endpoint averages before pruning and retained for 90 days. History and metric-explorer queries spanning more than ~36h transparently read the rollups, so 7-day (and longer) charts show real history instead of flat-lining past the raw window — without unbounded DB growth. Fully transparent to the UI (falls back to raw until the first rollup runs). New `sample_rollups` table; rollup runs each prune cycle (leader-only).

## [v0.76.0] — 2026-10-13
- Auto-response (SOAR-lite): playbooks that automatically network-isolate an endpoint the moment a detection fires matching a severity/rule filter — contained in seconds with no human in the loop (and won't re-isolate an already-contained host). Managed in Admin → Auto-response playbooks. `GET/POST/PUT/DELETE /api/v1/orgs/{id}/playbooks`.
- Alert silences / maintenance windows: suppress alert notifications (the alert is still recorded) for matching rule/endpoint until the window expires, so planned work doesn't page. Admin → Alert silences. `GET/POST/DELETE /api/v1/orgs/{id}/silences`.

## [v0.75.0] — 2026-10-13
- Threat-hunting console: a new "🔎 Threat hunt" view runs one ad-hoc search across security events and logs at once (free-text, with source / severity / time-window filters), results merged newest-first. Save a hunt for reuse, and promote any hunt to a recurring alert that fires when it matches at/above a threshold in a 5-minute window. API: `GET /api/v1/hunt` (search) and `GET/POST/DELETE /api/v1/hunts` (saved hunts); hunt alerts ride the existing engine (`hunt:<name>` rules).

## [v0.74.0] — 2026-10-13
- Detection engineering: behavioral detections are now manageable per org, not just hardcoded. In Admin → Detection rules you can toggle and re-severity the built-ins (reverse shell, backdoor listener, crypto miner, recon, exec storm), add custom field-match rules over the process / connection / listener streams, and **import Sigma rules** (a pragmatic subset: title/level/tags→MITRE, logsource category→stream, a detection selection → AND-of-fields / OR-of-values, with warnings for unsupported parts). New `detection_rules` + `detection_settings` tables; `GET/POST/PUT/DELETE /api/v1/orgs/{id}/detections` plus `/sigma` and `/builtin/{name}`.

## [v0.73.0] — 2026-10-13
- Temperature now defaults to °F (the metric explorer's °C/°F toggle still switches, and an explicit prior choice is preserved).

## [v0.72.0] — 2026-10-13
- Interactive charts: hovering any time-series chart (metric explorer, host detail, dashboards, synthetic latency, traces) now shows a crosshair plus a tooltip with the exact timestamp and each series' value + host at that point. Works everywhere `drawChart` is used.
- Temperature unit toggle: the metric explorer's Temperature view has a °C / °F switch (remembered per browser via localStorage); the axis and tooltip follow the chosen unit.

## [v0.71.0] — 2026-10-13
- Dashboard navigation redesign: the sidebar is now a proper grouped "Explore" menu — a cohesive set of monochrome line icons (replacing the mixed emoji), neutral text with hover + active states, an active indicator that tracks the current view, and no more per-row dividers. A cleaner, more professional look.

## [v0.70.0] — 2026-10-13
- Postgres automatic failover (pg_auto_failover): a monitor node (`varro-pg-mon`) arbitrates the primary (`varro-pg`) / secondary (`varro-pg-2`) pair and auto-promotes the standby on primary failure — lossless (synchronous `quorum` replication) and with no human action. Collectors now use a multi-host `target_session_attrs=read-write` DSN that transparently follows the primary, so failover needs no config change. Replaces the manual promote+repoint runbook ([docs/postgres-ha.md](docs/postgres-ha.md)). Verified end-to-end — controlled switchover and a primary-restart drill were both ridden automatically (health 200 throughout, zero data loss, old primary rejoined as a healthy secondary). Runbook: [docs/postgres-autofailover.md](docs/postgres-autofailover.md). (Infra + docs; no agent/binary change — collectors remain on v0.69.0.)

## [v0.69.0] — 2026-10-13
- Custom dashboards: named multi-panel layouts built on the metric explorer. In Metric explorer, pick a metric + hosts + window and click "📊 Add to dashboard"; the new "📊 Dashboards" view renders each dashboard as a responsive grid of charts (per-panel host legends), with per-panel remove and whole-dashboard delete. Owner-scoped like saved views. `GET/POST/DELETE /api/v1/dashboards`.

## [v0.68.0] — 2026-10-13
- Alert routing: per-org notification destinations (webhook, Slack, PagerDuty, Opsgenie), each with a minimum severity, additive to the collector's global webhook/Slack/email. Alerts fan out to every matching route — e.g. critical-only to PagerDuty, everything to Slack. PagerDuty uses Events API v2 (firing→trigger, resolved→resolve by dedup key); Opsgenie uses the Alerts API (create/close by alias). Managed per-org in Admin → Alert routing. `GET/POST/DELETE /api/v1/orgs/{id}/routes`. Webhook/Slack URLs are SSRF-guarded (same post-DNS IP policy as synthetic probes).

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
