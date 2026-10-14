# Agent platform support

The Varro agent is a single Go binary that runs on Linux, macOS, and Windows.
Most telemetry is cross-platform (gopsutil); the **deep behavioral sensors**
differ by OS. This documents what's active where, and the roadmap for full parity.

## Sensor matrix

| Signal | Linux | macOS | Windows |
|--------|-------|-------|---------|
| Host metrics (CPU/mem/disk/net/procs) | ✅ gopsutil | ✅ | ✅ |
| Listening ports, established connections, sessions | ✅ | ✅ | ✅ |
| Inventory (packages) | ✅ dpkg/rpm/pacman | ✅ (brew/pkgutil) | ✅ |
| Logs | ✅ journald | ✅ unified log (best-effort) | ✅ Event Log (best-effort) |
| **Process-start events** (`Execs`) | ✅ eBPF (short-lived) | ✅ polling (v0.80.0) | ✅ polling + ⚗️ ETW (opt-in, v0.84.0) |
| **Short-lived outbound connects** (`Conns`) | ✅ eBPF | ◻️ roadmap | ◻️ roadmap |
| File-integrity monitoring (FIM) | ✅ | ✅ | ✅ |
| Host isolation (response action) | ✅ nft/iptables | ✅ pf | ✅ WFP/netsh |

Because listening ports, established connections, and the top process list come
from gopsutil on every platform, **most detection rules already work everywhere**
— a miner running as a live process, a shell with an established socket, a
backdoor listener are all caught on macOS/Windows today. What was Linux-only is
the *short-lived* capture (processes/connections that start and exit between
samples), provided on Linux by the eBPF sensors.

## v0.80.0 — portable process-start sensor

`collect.PollExecTracer` diffs the process table each sample and reports
newly-appeared PIDs as exec events, satisfying the same `Drain()` interface the
eBPF sensor does. The agent uses it automatically wherever the eBPF sensor isn't
available (macOS, Windows, old/unprivileged Linux), so the detection engine's
process stream is now fed on all platforms.

Limitation vs eBPF: it catches every process still alive at the next poll, but
not one that starts *and* exits within a single sample interval. That's inherent
to polling.

## v0.83.0 — cross-platform log collection

`CollectLogs` now has per-OS implementations behind build tags:
- **Windows** (`logs_windows.go`): PowerShell `Get-WinEvent` over System +
  Application, incremental by a timestamp cursor, parsed from compact JSON.
- **macOS** (`logs_darwin.go`): `log show --style ndjson` over the unified log,
  incremental by a timestamp cursor, capped to the newest N.

Both are **best-effort**: they cross-compile and, per the agent's contract, any
failure (missing command, parse error) disables log capture gracefully rather
than crashing — so the worst case equals the previous "no logs" behavior. They
still need field validation on real Windows/macOS hosts (exact `log show`
predicate, `Get-WinEvent` field shapes, cursor boundary behavior).

## Roadmap — kernel-native deep sensors

True short-lived parity needs platform-native tracing, which is a larger effort
and (for macOS) needs packaging/signing infrastructure this project's
cross-compile release pipeline doesn't yet have:

- **Windows: ETW** (Event Tracing for Windows) — **implemented, opt-in,
  UNVALIDATED (v0.84.0).** `internal/etw/etw_windows.go` is a real-time consumer
  of the `Microsoft-Windows-Kernel-Process` provider's ProcessStart events
  (StartTraceW → EnableTraceEx2 → OpenTraceW → ProcessTrace). The agent tries it
  before the polling sensor, but ONLY when `VARRO_ETW=1` is set — because it is
  hand-rolled ETW syscall code (x/sys/windows ships no ETW types) that has not run
  on a real Windows host, and a wrong struct layout faults at the ProcessTrace
  syscall (an uncatchable crash, not a recoverable error). **To make it default-on:
  validate on a Windows host, fix the struct layouts / UserData parsing as needed
  (esp. `eventTraceLogfile`'s `CurrentEvent`/`LogfileHeader` sizes and the
  ProcessStart field offsets — ideally via TDH), then drop the `VARRO_ETW` gate in
  `Start()`.** `-Network` (TCP-connect) events are a further follow-up.
- **macOS: Endpoint Security Framework (ESF)** — `es_new_client` with
  `ES_EVENT_TYPE_NOTIFY_EXEC` / `..._CONNECT`. Requires cgo, a **signed system
  extension** with the `com.apple.developer.endpoint-security.client`
  entitlement, and notarization — i.e. an Apple Developer account and a signing
  step in the build, neither of which exists in the current pipeline.

Until then, the polling sensor provides broad, if coarser, cross-platform
coverage.
