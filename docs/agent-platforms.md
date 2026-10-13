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
| Logs | ✅ journald | ◻️ (none yet) | ◻️ (none yet) |
| **Process-start events** (`Execs`) | ✅ eBPF (short-lived) | ✅ **polling** (v0.80.0) | ✅ **polling** (v0.80.0) |
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

## Roadmap — kernel-native deep sensors

True short-lived parity needs platform-native tracing, which is a larger effort
and (for macOS) needs packaging/signing infrastructure this project's
cross-compile release pipeline doesn't yet have:

- **Windows: ETW** (Event Tracing for Windows) — subscribe to the
  `Microsoft-Windows-Kernel-Process` / `-Network` providers for process-create
  and TCP-connect events. Pure Go is feasible (`golang.org/x/sys/windows` +
  ETW consumer), but requires a Windows host to validate.
- **macOS: Endpoint Security Framework (ESF)** — `es_new_client` with
  `ES_EVENT_TYPE_NOTIFY_EXEC` / `..._CONNECT`. Requires cgo, a **signed system
  extension** with the `com.apple.developer.endpoint-security.client`
  entitlement, and notarization — i.e. an Apple Developer account and a signing
  step in the build, neither of which exists in the current pipeline.

Until then, the polling sensor provides broad, if coarser, cross-platform
coverage.
