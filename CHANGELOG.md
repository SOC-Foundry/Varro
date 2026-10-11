# Changelog

All notable changes to Varro. Each entry is a released git tag, newest first;
the format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Dates are commit dates (UTC).

Core agent + collector, alerting, per-agent enrollment tokens, and multi-tenant
orgs predate tagged releases (v0.1–v0.3).

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
