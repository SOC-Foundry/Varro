// Package model defines the telemetry types shared by the Varro agent,
// collector server, and CLI.
package model

import "time"

// Snapshot is one full telemetry sample from an endpoint.
type Snapshot struct {
	AgentID      string          `json:"agent_id"`
	AgentVersion string          `json:"agent_version"`
	Hostname     string          `json:"hostname"`
	Timestamp    time.Time       `json:"timestamp"`
	Host         HostInfo        `json:"host"`
	CPU          CPUMetrics      `json:"cpu"`
	Memory       MemoryMetrics   `json:"memory"`
	Disks        []DiskMetrics   `json:"disks"`
	Network      NetworkMetrics  `json:"network"`
	Hardware     HardwareMetrics `json:"hardware"`
	Processes    []ProcessInfo   `json:"processes"`
	Security     SecurityMetrics `json:"security"`
	// Posture and Health are recomputed every few minutes and carried on
	// every snapshot in between.
	Posture []PostureCheck `json:"posture,omitempty"`
	Health  HealthStatus   `json:"health"`
	// Inventory is only present when the package set changed since the last
	// shipped inventory (or on the agent's first scan).
	Inventory *Inventory `json:"inventory,omitempty"`
	// Events are state changes the agent observed since the previous sample
	// (new process, new listening port, autostart modification, ...).
	Events []Event `json:"events,omitempty"`
	// ProcHashes are SHA-256 digests of newly-seen process binaries this
	// sample, for server-side malware-hash matching.
	ProcHashes []ProcHash `json:"proc_hashes,omitempty"`
	// Containers running on the endpoint (empty when no runtime is present).
	Containers []ContainerInfo `json:"containers,omitempty"`
	// EBPF indicates the kernel exec sensor is active; Execs are distinct
	// process execs it captured since the last sample — including short-lived
	// ones the periodic process scan would miss.
	EBPF  bool         `json:"ebpf"`
	Execs []ExecSample `json:"execs,omitempty"`
	// Conns are short-lived outbound connects captured by the eBPF connect
	// sensor since the last sample (process-attributed).
	Conns []ConnSample `json:"conns,omitempty"`
	// DeclaredDeps are configured ("declared") dependencies parsed from the host
	// (systemd unit ordering + Postgres/HA connection config), as opposed to the
	// dependencies observed from live traffic. Refreshed periodically.
	DeclaredDeps []DeclaredDep `json:"declared_deps,omitempty"`
}

// Declared-dependency kinds.
const (
	DepKindSystemd     = "systemd"     // local service→service ordering/requirement
	DepKindReplication = "replication" // Postgres streaming replication (standby→primary)
	DepKindHAMonitor   = "ha-monitor"  // pg_auto_failover node→monitor
	DepKindDatabase    = "database"    // a service's Postgres DSN (service→DB host)
)

// DeclaredDep is a configured dependency the agent read from host config, not one
// inferred from observed traffic. Cross-host deps (TargetHost set) become overlay
// edges on the topology graph; host-local ones (systemd) show in the node inspector.
type DeclaredDep struct {
	Kind       string `json:"kind"`                  // systemd | replication | ha-monitor
	From       string `json:"from,omitempty"`        // local service/role (e.g. "varro-server.service", "postgres")
	Target     string `json:"target,omitempty"`      // target unit (systemd) or human descriptor
	TargetHost string `json:"target_host,omitempty"` // cross-host dep: IP/host of the dependency
	TargetPort int    `json:"target_port,omitempty"`
	Hard       bool   `json:"hard,omitempty"` // Requires/BindsTo (hard) vs After/Wants (ordering)
}

// ExecSample is one process exec observed by the eBPF sensor.
type ExecSample struct {
	PID  uint32 `json:"pid"`
	Comm string `json:"comm"`
}

// ConnSample is one short-lived outbound TCP connect observed by the eBPF
// sensor — process-attributed, catching connections the periodic scan misses.
type ConnSample struct {
	PID  uint32 `json:"pid"`
	Comm string `json:"comm"`
	Dest string `json:"dest"`
	Port uint16 `json:"port"`
}

// ProcHash is the SHA-256 of a newly-observed process's executable.
type ProcHash struct {
	PID    int32  `json:"pid"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// HardwareMetrics carries sensor readings and device I/O rates.
type HardwareMetrics struct {
	Temps  []TempReading `json:"temps,omitempty"`
	DiskIO []DiskIORate  `json:"disk_io,omitempty"`
}

type TempReading struct {
	Sensor  string  `json:"sensor"`
	Celsius float64 `json:"celsius"`
	High    float64 `json:"high,omitempty"` // sensor's own warning threshold, 0 if unknown
}

// DiskIORate is per-device I/O computed from counter deltas between samples.
type DiskIORate struct {
	Device    string  `json:"device"`
	ReadBps   float64 `json:"read_bps"`
	WriteBps  float64 `json:"write_bps"`
	ReadIOPS  float64 `json:"read_iops"`
	WriteIOPS float64 `json:"write_iops"`
}

// Posture check statuses.
const (
	PosturePass = "pass"
	PostureFail = "fail"
	PostureNA   = "na" // not applicable / not determinable on this platform
)

// PostureCheck is one CIS-lite configuration audit result.
type PostureCheck struct {
	ID     string `json:"id"`
	Desc   string `json:"desc"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// HealthStatus is the endpoint's patch/service health.
type HealthStatus struct {
	PendingUpdates int      `json:"pending_updates"`
	RebootRequired bool     `json:"reboot_required"`
	FailedServices []string `json:"failed_services,omitempty"`
}

// Inventory is the endpoint's installed-software state.
type Inventory struct {
	Kernel   string    `json:"kernel"`
	Manager  string    `json:"manager"` // dpkg, rpm, pacman
	Packages []Package `json:"packages"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SecurityMetrics is the security-relevant state of the endpoint.
type SecurityMetrics struct {
	ListeningPorts   []ListeningPort `json:"listening_ports"`
	EstablishedConns int             `json:"established_conns"`
	// Connections are established outbound/inbound connections with process
	// attribution, capped and deduplicated by (remote, pid).
	Connections []OutboundConn `json:"connections,omitempty"`
	Sessions    []SessionInfo  `json:"sessions"`
	// FailedAuths counts failed authentication log lines observed since the
	// previous sample (best effort; 0 when the auth log is unreadable).
	FailedAuths int `json:"failed_auths"`
}

type ListeningPort struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	PID     int32  `json:"pid"`
	Process string `json:"process"`
}

type OutboundConn struct {
	Proto      string `json:"proto"`
	Local      string `json:"local"`
	Remote     string `json:"remote"`
	RemoteName string `json:"remote_name,omitempty"` // reverse-DNS, filled by the server
	Domain     string `json:"domain,omitempty"`      // forward DNS/SNI name, filled by the agent's watcher
	PID        int32  `json:"pid"`
	Process    string `json:"process"`
}

type SessionInfo struct {
	User     string `json:"user"`
	Terminal string `json:"terminal"`
	Host     string `json:"host"`
	Started  int64  `json:"started"`
}

// Event types emitted by the agent.
const (
	EventProcessNew        = "process_new"
	EventListenNew         = "listen_new"
	EventNICNew            = "nic_new"
	EventAutostartChange   = "autostart_change"
	EventUserLogin         = "user_login"
	EventAuthFailures      = "auth_failures"
	EventIdentityChange    = "identity_change" // passwd/group/sudoers/authorized_keys
	EventSUIDChange        = "suid_change"
	EventPkgInstall        = "pkg_install"
	EventPkgRemove         = "pkg_remove"
	EventPkgUpgrade        = "pkg_upgrade"
	EventPostureChange     = "posture_change"
	EventServiceFailed     = "service_failed"
	EventRebootRequired    = "reboot_required"
	EventFIMChange         = "fim_change"
	EventConnNewInternal   = "conn_new_internal"   // first-seen fleet-internal communication path
	EventVulnNew           = "vuln_new"            // package newly matched to a known vulnerability
	EventThreatMatch       = "threat_match"        // connection to a known-malicious indicator
	EventMalwareMatch      = "malware_match"       // process binary matched a known-malware hash
	EventContainerNew      = "container_new"       // container started
	EventContainerGone     = "container_gone"      // container stopped
	EventDetection         = "detection"           // behavioral detection fired
	EventDomainThreatMatch = "domain_threat_match" // connection to a known-malicious domain
	EventDomainNew         = "domain_new"          // first-seen external domain for this org
	EventCICD              = "cicd"                // CI/CD pipeline event (build/deploy/release) via webhook
	EventDeployRegression  = "deploy_regression"   // a deploy correlated with a service error/latency regression
)

// Response action types. This is an exhaustive allowlist — the agent executes
// nothing outside it, and in particular never runs an operator-supplied
// command string.
const (
	ActionKillProcess = "kill_process" // Arg = PID
	ActionIsolate     = "isolate"      // network containment (keeps agent->collector)
	ActionUnisolate   = "unisolate"    // lift containment
)

// ValidActionType reports whether t is an allowlisted action.
func ValidActionType(t string) bool {
	switch t {
	case ActionKillProcess, ActionIsolate, ActionUnisolate:
		return true
	}
	return false
}

// Action statuses.
const (
	ActionPending = "pending"
	ActionSent    = "sent"
	ActionDone    = "done"
	ActionFailed  = "failed"
)

// Action is an operator-issued response command for one endpoint.
type Action struct {
	ID         int64      `json:"id"`
	EndpointID string     `json:"endpoint_id"`
	Type       string     `json:"type"`
	Arg        string     `json:"arg,omitempty"`
	Status     string     `json:"status"`
	Result     string     `json:"result,omitempty"`
	IssuedBy   string     `json:"issued_by"`
	IssuedAt   time.Time  `json:"issued_at"`
	DoneAt     *time.Time `json:"done_at,omitempty"`
}

// AuditEntry is one recorded administrative action.
type AuditEntry struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	OrgID     string    `json:"org_id,omitempty"`
	Target    string    `json:"target,omitempty"`
}

// Vulnerability is one OSV finding against an installed package.
type Vulnerability struct {
	ID       string `json:"id"` // OSV/CVE identifier
	Package  string `json:"package"`
	Version  string `json:"version"`
	Severity string `json:"severity,omitempty"` // as reported by the source DB, when available
	Summary  string `json:"summary,omitempty"`
}

// TopoNode and TopoEdge describe the fleet communication graph.
type TopoNode struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Online   bool   `json:"online"`
	// Risk: "" (ok), "warn", "high" (exposed + unpatched), "critical" (active
	// detection/threat). RiskReasons explains the rating.
	Risk        string   `json:"risk,omitempty"`
	RiskReasons []string `json:"risk_reasons,omitempty"`
	Group       string   `json:"group,omitempty"`      // cloud acct/region grouping (or ASN for external nodes)
	Containers  int      `json:"containers,omitempty"` // running container count
	Platform    string   `json:"platform,omitempty"`
	External    bool     `json:"external,omitempty"` // an external destination (website/service), not a fleet host
	// DeclaredDeps are this host's configured service-level dependencies (systemd
	// ordering/requirements), shown in the node inspector. Populated only when the
	// declared overlay is requested.
	DeclaredDeps []DeclaredDep `json:"declared_deps,omitempty"`
}

type EdgeProcess struct {
	Process    string `json:"process"`               // the calling (source) process
	Port       int    `json:"port"`                  // the destination port it connected to
	DstProcess string `json:"dst_process,omitempty"` // process listening on that port at the callee (resolved passively)
}

type TopoEdge struct {
	Src         string        `json:"src"`
	Dst         string        `json:"dst"` // endpoint ID, or "internet"
	Internal    bool          `json:"internal"`
	Processes   []EdgeProcess `json:"processes"`
	Count       int           `json:"count"`           // external: connection count; internal: process/port pairs
	Bytes       uint64        `json:"bytes,omitempty"` // external: total conntrack bytes to these remotes
	FirstSeen   time.Time     `json:"first_seen,omitempty"`
	LastSeen    time.Time     `json:"last_seen,omitempty"`
	Remotes     []string      `json:"remotes,omitempty"`      // external edges: sample remote IPs
	RemoteNames []string      `json:"remote_names,omitempty"` // reverse-DNS of Remotes, same order ("" when unresolved)
	RemoteGeo   []string      `json:"remote_geo,omitempty"`   // "country/ASN" of Remotes, same order (when GeoIP enabled)
	Malicious   bool          `json:"malicious,omitempty"`    // a remote matches the threat-intel feed
	// Declared marks an edge that comes from configured dependency (systemd/pg
	// config) rather than observed traffic. DepKind names the source; Hard is a
	// requirement vs. ordering/best-effort.
	Declared bool   `json:"declared,omitempty"`
	DepKind  string `json:"dep_kind,omitempty"`
	Hard     bool   `json:"hard,omitempty"`
}

type Event struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// StoredEvent is an event as returned by the server, with provenance.
type StoredEvent struct {
	ID         int64     `json:"id"`
	OrgID      string    `json:"org_id"`
	EndpointID string    `json:"endpoint_id"`
	Hostname   string    `json:"hostname"`
	Timestamp  time.Time `json:"timestamp"`
	Type       string    `json:"type"`
	Message    string    `json:"message"`
}

// AlertRule is a server-side threshold rule. Metric is one of the stored
// sample columns (cpu_pct, mem_pct, disk_pct, swap_pct, rx_rate, tx_rate) or
// the special value "offline".
type AlertRule struct {
	Name       string  `json:"name"`
	Metric     string  `json:"metric"`
	Op         string  `json:"op"` // ">" or "<"; ignored for offline
	Threshold  float64 `json:"threshold"`
	ForSeconds int     `json:"for_seconds"`
}

const (
	AlertFiring   = "firing"
	AlertResolved = "resolved"
)

type Alert struct {
	ID         int64      `json:"id"`
	OrgID      string     `json:"org_id"`
	Rule       string     `json:"rule"`
	EndpointID string     `json:"endpoint_id"`
	Hostname   string     `json:"hostname"`
	State      string     `json:"state"`
	Message    string     `json:"message"`
	Value      float64    `json:"value"`
	StartedAt  time.Time  `json:"started_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	// Incident lifecycle (operator workflow on top of auto fire/resolve).
	AckBy    string     `json:"ack_by,omitempty"`   // who acknowledged it
	AckAt    *time.Time `json:"ack_at,omitempty"`   // when acknowledged
	Assignee string     `json:"assignee,omitempty"` // owner handling it
	Note     string     `json:"note,omitempty"`     // resolution / operator note
}

// HostInfo describes the endpoint itself; it changes rarely.
type HostInfo struct {
	OS              string     `json:"os"`
	Platform        string     `json:"platform"`
	PlatformVersion string     `json:"platform_version"`
	KernelVersion   string     `json:"kernel_version"`
	Arch            string     `json:"arch"`
	Uptime          uint64     `json:"uptime_seconds"`
	BootTime        int64      `json:"boot_time"`
	NumProcs        uint64     `json:"num_procs"`
	Cloud           *CloudInfo `json:"cloud,omitempty"`
}

// CloudInfo ties an endpoint to its cloud workload identity.
type CloudInfo struct {
	Provider     string `json:"provider"` // gcp, aws, azure
	AccountID    string `json:"account_id"`
	Region       string `json:"region"`
	Zone         string `json:"zone"`
	InstanceID   string `json:"instance_id"`
	InstanceType string `json:"instance_type"`
	Identity     string `json:"identity"` // service account / IAM role
}

// ContainerInfo is one running container on the endpoint.
type ContainerInfo struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Image     string  `json:"image"`
	Status    string  `json:"status"`
	Pod       string  `json:"pod,omitempty"`
	Namespace string  `json:"namespace,omitempty"`
	CPUPct    float64 `json:"cpu_percent,omitempty"`
	MemBytes  uint64  `json:"mem_bytes,omitempty"`
}

type CPUMetrics struct {
	TotalPercent float64   `json:"total_percent"`
	PerCore      []float64 `json:"per_core_percent"`
	Cores        int       `json:"cores"`
	Load1        float64   `json:"load1"`
	Load5        float64   `json:"load5"`
	Load15       float64   `json:"load15"`
}

type MemoryMetrics struct {
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Available   uint64  `json:"available"`
	UsedPercent float64 `json:"used_percent"`
	SwapTotal   uint64  `json:"swap_total"`
	SwapUsed    uint64  `json:"swap_used"`
}

type DiskMetrics struct {
	Mountpoint  string  `json:"mountpoint"`
	Fstype      string  `json:"fstype"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	UsedPercent float64 `json:"used_percent"`
}

type NetworkMetrics struct {
	// RxRate/TxRate are whole-host byte rates computed by the agent from
	// counter deltas between consecutive samples.
	RxRate     float64          `json:"rx_rate_bps"`
	TxRate     float64          `json:"tx_rate_bps"`
	Interfaces []InterfaceStats `json:"interfaces"`
	// Flows are per-remote byte-counted flows from the kernel conntrack table
	// (Linux, when conntrack accounting is available). Continuous — includes
	// short-lived connections the point-in-time table would miss.
	Flows []Flow `json:"flows,omitempty"`
}

// Flow is a byte-counted connection aggregate to one remote endpoint.
type Flow struct {
	Proto    string `json:"proto"`
	Remote   string `json:"remote"` // ip:port
	BytesOut uint64 `json:"bytes_out"`
	BytesIn  uint64 `json:"bytes_in"`
	// Domain is the hostname the remote IP was resolved from, when the agent's
	// passive DNS/SNI watcher observed it (e.g. "api.stripe.com"). Far more
	// useful than reverse-DNS for CDN/cloud IPs.
	Domain string `json:"domain,omitempty"`
}

type InterfaceStats struct {
	Name        string   `json:"name"`
	Addrs       []string `json:"addrs,omitempty"` // non-loopback, non-link-local IPs
	BytesSent   uint64   `json:"bytes_sent"`
	BytesRecv   uint64   `json:"bytes_recv"`
	PacketsSent uint64   `json:"packets_sent"`
	PacketsRecv uint64   `json:"packets_recv"`
	ErrIn       uint64   `json:"err_in"`
	ErrOut      uint64   `json:"err_out"`
	RxRate      float64  `json:"rx_rate_bps"` // computed from deltas, 0 on first sample
	TxRate      float64  `json:"tx_rate_bps"`
}

type ProcessInfo struct {
	PID        int32   `json:"pid"`
	Name       string  `json:"name"`
	Username   string  `json:"username"`
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float32 `json:"mem_percent"`
	RSS        uint64  `json:"rss"`
	Cmdline    string  `json:"cmdline"`
}

// DefaultOrg is the organization that legacy (master-token) agents and
// pre-multi-tenant data belong to.
const DefaultOrg = "default"

// Org is a tenant: a customer or team whose endpoints, alerts, and events are
// isolated from every other tenant's.
type Org struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// AutoJoinDomain, when set, automatically adds anyone signing in with a
	// verified email at this domain as a member of this org.
	AutoJoinDomain string `json:"auto_join_domain,omitempty"`
	// Infrastructure marks an org as holding monitoring infrastructure (e.g. the
	// collectors themselves). Such orgs are excluded from the "all orgs"
	// compliance aggregate so they don't skew tenant numbers.
	Infrastructure bool      `json:"infrastructure,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// User is a dashboard user authenticated via Google sign-in.
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Admin bool   `json:"admin"` // instance admin: sees all orgs, manages orgs/tokens
}

// OrgMember is one row of an org's membership.
type OrgMember struct {
	Email string `json:"email"`
	Role  string `json:"role"` // "member" or "admin" (org admin: manages this org)
}

// ComplianceReport is an org-wide rollup of posture, vulnerabilities, and
// patch health for auditing/reporting.
type ComplianceReport struct {
	GeneratedAt    time.Time      `json:"generated_at"`
	Endpoints      int            `json:"endpoints"`
	Online         int            `json:"online"`
	OSBreakdown    map[string]int `json:"os_breakdown"`
	PostureScore   int            `json:"posture_score"` // % of pass over pass+fail
	PosturePass    int            `json:"posture_pass"`
	PostureFail    int            `json:"posture_fail"`
	PostureChecks  []PostureStat  `json:"posture_checks"` // per-check aggregate across the fleet
	Vulns          map[string]int `json:"vulns"`          // severity -> count
	VulnTotal      int            `json:"vuln_total"`
	PendingUpdates int            `json:"pending_updates"` // summed across endpoints
	RebootRequired int            `json:"reboot_required"` // endpoints needing a reboot
	FailedServices int            `json:"failed_services"` // endpoints with a failed service
}

// OTLPMetric is one data point pushed via OTLP (OpenTelemetry) by an app.
type OTLPMetric struct {
	Service string  `json:"service"`
	Metric  string  `json:"metric"`
	TS      int64   `json:"ts"` // unix seconds
	Value   float64 `json:"value"`
	Attrs   string  `json:"attrs,omitempty"` // flattened point attributes "k=v,k=v"
}

// OTLPMetricSummary rolls up one service+metric over a window for the custom-
// metrics view: how many points, and the latest value.
type OTLPMetricSummary struct {
	Service   string  `json:"service"`
	Metric    string  `json:"metric"`
	LastValue float64 `json:"last_value"`
	LastTS    int64   `json:"last_ts"`
	Count     int     `json:"count"`
}

// OTLPSpan is one span pushed via OTLP tracing.
type OTLPSpan struct {
	TraceID  string `json:"trace_id"`
	SpanID   string `json:"span_id"`
	ParentID string `json:"parent_id,omitempty"`
	Service  string `json:"service"`
	Name     string `json:"name"`
	Kind     string `json:"kind,omitempty"`
	StartNs  int64  `json:"start_ns"`
	DurNs    int64  `json:"dur_ns"`
	Status   string `json:"status,omitempty"` // "", "ok", "error"
	Attrs    string `json:"attrs,omitempty"`
	TS       int64  `json:"ts"` // unix seconds (start), for windowing
}

// ServiceHealth is the RED rollup for one service over a window, computed from
// its root spans (parent-less spans = top-level requests).
type ServiceHealth struct {
	Service   string  `json:"service"`
	Requests  int     `json:"requests"`
	Errors    int     `json:"errors"`
	ErrorRate float64 `json:"error_rate"` // 0..1
	ReqPerMin float64 `json:"req_per_min"`
	P50Ms     float64 `json:"p50_ms"`
	P95Ms     float64 `json:"p95_ms"`
	P99Ms     float64 `json:"p99_ms"`
}

// OTLPTraceSummary rolls one trace (all spans sharing a trace id) into a row for
// the traces list: root operation, service, wall-clock duration, span count.
type OTLPTraceSummary struct {
	TraceID    string  `json:"trace_id"`
	Service    string  `json:"service"`
	Operation  string  `json:"operation"`
	StartTS    int64   `json:"start_ts"`
	DurationMs float64 `json:"duration_ms"`
	SpanCount  int     `json:"span_count"`
	Error      bool    `json:"error,omitempty"`
}

// ServiceEdge is one caller→callee dependency derived from spans whose parent
// runs in a different service: the parent's service called the child's service.
// Metrics are measured on the callee (child) span — the downstream work.
type ServiceEdge struct {
	Caller    string  `json:"caller"`
	Callee    string  `json:"callee"`
	Calls     int     `json:"calls"`
	Errors    int     `json:"errors"`
	ErrorRate float64 `json:"error_rate"` // 0..1
	P50Ms     float64 `json:"p50_ms"`
	P95Ms     float64 `json:"p95_ms"`
}

// ServiceNode is a vertex in the dependency graph with its in/out call totals.
type ServiceNode struct {
	Service  string `json:"service"`
	Incoming int    `json:"incoming"` // calls received (as callee)
	Outgoing int    `json:"outgoing"` // calls made (as caller)
	Errors   int    `json:"errors"`   // errors on calls it received
	Root     bool   `json:"root"`     // has root (parent-less) spans = entrypoint
}

// ServiceGraph is the service-to-service dependency map over a window.
type ServiceGraph struct {
	Nodes []ServiceNode `json:"nodes"`
	Edges []ServiceEdge `json:"edges"`
}

// IOC indicator types.
const (
	IOCTypeIP     = "ip"
	IOCTypeDomain = "domain"
	IOCTypeHash   = "hash"
)

// IOC is a persisted per-org indicator of compromise (a known-bad IP, domain, or
// file hash), either entered manually or ingested from a STIX/TAXII feed. These
// supplement the global keyless feeds and are matched against endpoint telemetry.
type IOC struct {
	OrgID   string `json:"org_id,omitempty"`
	Type    string `json:"type"`   // ip | domain | hash
	Value   string `json:"value"`  // normalized (lowercased for domain/hash)
	Source  string `json:"source"` // "manual" or the feed URL
	Label   string `json:"label,omitempty"`
	AddedAt int64  `json:"added_at"`
}

// IOCCounts is the per-type tally of an org's IOCs, for the management view.
type IOCCounts struct {
	IP     int `json:"ip"`
	Domain int `json:"domain"`
	Hash   int `json:"hash"`
}

// STIXFeed is a per-org configured STIX 2.1 / TAXII 2.1 indicator feed URL that
// the server polls on a schedule, upserting the indicators it yields as IOCs.
type STIXFeed struct {
	ID         string `json:"id"`
	OrgID      string `json:"org_id,omitempty"`
	URL        string `json:"url"`
	Kind       string `json:"kind"` // stix (bundle URL) | taxii (collection objects URL)
	Enabled    bool   `json:"enabled"`
	AddedAt    int64  `json:"added_at"`
	LastRun    int64  `json:"last_run,omitempty"`
	LastCount  int    `json:"last_count,omitempty"`
	LastStatus string `json:"last_status,omitempty"`
}

// SavedView is a named, persisted metric-explorer configuration (its spec is an
// opaque JSON blob the dashboard interprets: metric, endpoints, time range).
type SavedView struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Spec      string    `json:"spec"`
	CreatedAt time.Time `json:"created_at"`
}

// ReportSchedule is a per-org recurring email digest configuration.
type ReportSchedule struct {
	OrgID      string    `json:"org_id"`
	Enabled    bool      `json:"enabled"`
	Cadence    string    `json:"cadence"` // daily|weekly
	Recipients []string  `json:"recipients"`
	LastSent   time.Time `json:"last_sent,omitempty"`
}

// Incident statuses.
const (
	IncidentOpen     = "open"
	IncidentAck      = "acknowledged"
	IncidentResolved = "resolved"
)

// Incident groups related alerts + detections for one endpoint into a single
// triage unit with a timeline, status, and owner.
type Incident struct {
	ID         int64          `json:"id"`
	OrgID      string         `json:"org_id"`
	EndpointID string         `json:"endpoint_id"`
	Hostname   string         `json:"hostname"`
	Title      string         `json:"title"`
	Status     string         `json:"status"`
	Severity   string         `json:"severity"` // CRITICAL|HIGH|MEDIUM|LOW (max over items)
	Assignee   string         `json:"assignee,omitempty"`
	ItemCount  int            `json:"item_count"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	ResolvedAt *time.Time     `json:"resolved_at,omitempty"`
	Items      []IncidentItem `json:"items,omitempty"` // timeline, only on detail
}

// IncidentItem is one entry on an incident's timeline.
type IncidentItem struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"ts"`
	Kind      string    `json:"kind"` // alert|detection|note|status
	Actor     string    `json:"actor,omitempty"`
	Message   string    `json:"message"`
}

// Playbook is an automated response: when a detection fires matching its
// criteria, Varro runs Action against the affected endpoint (SOAR-lite).
type Playbook struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"org_id"`
	Name       string    `json:"name"`
	Enabled    bool      `json:"enabled"`
	OnSeverity string    `json:"on_severity,omitempty"` // "" = any; else fire at/above this (LOW<MEDIUM<HIGH<CRITICAL)
	OnRule     string    `json:"on_rule,omitempty"`     // "" = any; else substring match on the detection rule
	Action     string    `json:"action"`                // "isolate"
	CreatedAt  time.Time `json:"created_at"`
}

// Silence suppresses alert notifications (not the alert record) for matching
// alerts until Until — a maintenance window.
type Silence struct {
	ID            string    `json:"id"`
	OrgID         string    `json:"org_id"`
	Name          string    `json:"name"`
	MatchRule     string    `json:"match_rule,omitempty"`     // "" = any; else substring on rule name
	MatchEndpoint string    `json:"match_endpoint,omitempty"` // "" = any; else exact endpoint id
	Until         time.Time `json:"until"`
	CreatedAt     time.Time `json:"created_at"`
}

// HuntResult is one unified row in a threat-hunt search (an event or a log line
// normalized to a common shape).
type HuntResult struct {
	Source     string `json:"source"` // "event" | "log"
	TS         int64  `json:"ts"`
	EndpointID string `json:"endpoint_id"`
	Hostname   string `json:"hostname"`
	Kind       string `json:"kind"` // event type, or log severity
	Message    string `json:"message"`
}

// Hunt is a saved threat-hunt query, optionally promoted to a recurring alert.
type Hunt struct {
	ID        int64     `json:"id"`
	OrgID     string    `json:"org_id,omitempty"`
	Name      string    `json:"name"`
	Query     string    `json:"query"`              // free-text substring
	Source    string    `json:"source"`             // all|events|logs
	Severity  string    `json:"severity,omitempty"` // log severity filter
	Alerting  bool      `json:"alerting"`           // fire an alert when matches ≥ Threshold
	Threshold int       `json:"threshold"`          // over a 5-minute window
	CreatedAt time.Time `json:"created_at"`
}

// Detection-rule streams (what a custom rule matches against) and the fields
// available on each.
const (
	DetStreamProcess    = "process"    // fields: image, command, user
	DetStreamConnection = "connection" // fields: image, dest, port, domain
	DetStreamListener   = "listener"   // fields: image, port, address
)

// DetCond is one field match within a rule. A condition matches a document if
// the document's Field satisfies Op against ANY of Values (OR within a field);
// a rule matches when ALL its conditions match (AND across fields) — the shape
// of a single Sigma "selection".
type DetCond struct {
	Field  string   `json:"field"`
	Op     string   `json:"op"` // equals|contains|startswith|endswith|regex
	Values []string `json:"values"`
}

// DetectionRule is an operator-defined (or Sigma-imported) behavioral detection,
// evaluated per snapshot alongside the built-in rules.
type DetectionRule struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"org_id"`
	Name       string    `json:"name"`
	Enabled    bool      `json:"enabled"`
	Severity   string    `json:"severity"` // CRITICAL|HIGH|MEDIUM|LOW
	MITRE      string    `json:"mitre,omitempty"`
	Stream     string    `json:"stream"`
	Conditions []DetCond `json:"conditions"`
	Source     string    `json:"source,omitempty"` // "custom" | "sigma"
	CreatedAt  time.Time `json:"created_at"`
}

// DetectionSetting is a per-org override of a built-in detection rule (toggle it
// off, or change its severity).
type DetectionSetting struct {
	RuleName string `json:"rule"`
	Enabled  bool   `json:"enabled"`
	Severity string `json:"severity,omitempty"` // "" = keep the rule's default
}

// BuiltinRuleInfo describes a built-in detection rule for the management UI.
type BuiltinRuleInfo struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	MITRE    string `json:"mitre"`
	Desc     string `json:"desc"`
}

// Dashboard is a named, persisted multi-panel layout. Its Spec is an opaque
// JSON blob the dashboard UI interprets: {"panels":[{title,metric,minutes,endpoints}]}.
type Dashboard struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Spec      string    `json:"spec"`
	CreatedAt time.Time `json:"created_at"`
}

// VulnPriority ranks one endpoint's vulnerability exposure by runtime
// reachability — the "what to patch first" signal: raw CVSS weight scaled by
// how reachable/active the host actually is.
type VulnPriority struct {
	EndpointID     string   `json:"endpoint_id"`
	Hostname       string   `json:"hostname"`
	Score          int      `json:"score"`
	Critical       int      `json:"critical"`
	High           int      `json:"high"`
	Medium         int      `json:"medium"`
	Low            int      `json:"low"`
	Total          int      `json:"total"`
	InternetFacing bool     `json:"internet_facing,omitempty"`
	Malicious      bool     `json:"malicious,omitempty"` // talks to a known-malicious destination
	Online         bool     `json:"online"`
	Reasons        []string `json:"reasons,omitempty"` // human-readable ranking drivers
}

// Synthetic-check types.
const (
	ProbeHTTP = "http"
	ProbeTCP  = "tcp"
)

// Notification severities, lowest to highest. A route fires for alerts at or
// above its MinSeverity.
const (
	SevInfo     = "info"
	SevWarning  = "warning"
	SevCritical = "critical"
)

// Notification route types.
const (
	RouteWebhook   = "webhook"   // generic JSON POST
	RouteSlack     = "slack"     // Slack incoming webhook ({"text":...})
	RoutePagerDuty = "pagerduty" // PagerDuty Events API v2 (Target = routing key)
	RouteOpsgenie  = "opsgenie"  // Opsgenie Alerts API (Target = GenieKey)
)

// NotifyRoute is a per-org notification destination. Routes are additive to the
// collector's global webhook/Slack/email config: an org's alerts fan out to
// every one of its enabled routes whose MinSeverity the alert meets, plus the
// global destinations.
type NotifyRoute struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	Type        string    `json:"type"`         // webhook|slack|pagerduty|opsgenie
	Target      string    `json:"target"`       // URL (webhook/slack) or integration/routing key (pagerduty/opsgenie)
	MinSeverity string    `json:"min_severity"` // info|warning|critical
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// SyntheticCheck is an operator-configured active uptime probe: the collector
// periodically reaches out to Target and records whether it responds. Unlike
// the rest of Varro's telemetry (passively reported by agents), this is an
// outbound check the collector itself performs.
type SyntheticCheck struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"org_id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`                    // "http" | "tcp"
	Target     string    `json:"target"`                  // URL (http) or host:port (tcp)
	IntervalS  int       `json:"interval_seconds"`        // how often to probe
	ExpectCode int       `json:"expect_status,omitempty"` // http: required status (0 = any 2xx)
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
}

// ProbeResult is one recorded outcome of a synthetic check.
type ProbeResult struct {
	CheckID   string  `json:"check_id"`
	TS        int64   `json:"ts"` // unix seconds
	OK        bool    `json:"ok"`
	LatencyMs float64 `json:"latency_ms"`
	Code      int     `json:"code,omitempty"`  // HTTP status, when applicable
	Error     string  `json:"error,omitempty"` // short failure reason when !ok
}

// SyntheticStatus is a check plus its current health for the uptime view.
type SyntheticStatus struct {
	SyntheticCheck
	Up          bool    `json:"up"` // latest probe succeeded
	LastLatency float64 `json:"last_latency_ms"`
	LastCode    int     `json:"last_code,omitempty"`
	LastError   string  `json:"last_error,omitempty"`
	LastTS      int64   `json:"last_ts,omitempty"`
	UptimePct   float64 `json:"uptime_pct"` // over the last 24h
	Samples24h  int     `json:"samples_24h"`
}

// LogEntry is a single collected log line shipped from an endpoint (e.g. a
// journald record). Severity follows syslog names (emergency..debug) or "".
type LogEntry struct {
	TS       int64  `json:"ts"`                 // unix seconds
	Severity string `json:"severity,omitempty"` // emergency|alert|critical|error|warning|notice|info|debug
	Source   string `json:"source,omitempty"`   // systemd unit or syslog identifier
	Message  string `json:"message"`
}

// StoredLog is a log line as returned by the query API, with provenance.
type StoredLog struct {
	OrgID      string `json:"org_id"`
	EndpointID string `json:"endpoint_id"`
	Hostname   string `json:"hostname"`
	TS         int64  `json:"ts"`
	Severity   string `json:"severity,omitempty"`
	Source     string `json:"source,omitempty"`
	Message    string `json:"message"`
}

// FlowTalker is one external destination in the fleet's top-talkers rollup:
// total bytes, connection count, and how many fleet hosts reached it.
type FlowTalker struct {
	Dest      string `json:"dest"`              // domain or "internet"
	Bytes     uint64 `json:"bytes"`             // total conntrack bytes (in+out)
	Count     int    `json:"count"`             // connection count
	Sources   int    `json:"sources"`           // distinct fleet hosts talking to it
	Geo       string `json:"geo,omitempty"`     // "US · AS15169 Google" style
	Country   string `json:"country,omitempty"` // ISO alpha-2, for the map
	CDN       bool   `json:"cdn,omitempty"`     // CDN/anycast dest — geo is unreliable, don't plot by country
	Malicious bool   `json:"malicious,omitempty"`
}

// PostureStat aggregates one CIS-lite check across the fleet.
type PostureStat struct {
	ID   string `json:"id"`
	Desc string `json:"desc"`
	Pass int    `json:"pass"`
	Fail int    `json:"fail"`
}

// OrgTokenInfo describes an enrollment token without revealing it.
type OrgTokenInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// UserTokenInfo describes a personal API token without revealing its value.
type UserTokenInfo struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
}

// EndpointSummary is what the server returns when listing endpoints.
type EndpointSummary struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	Platform     string    `json:"platform"`
	Arch         string    `json:"arch"`
	Cores        int       `json:"cores"`
	MemTotal     uint64    `json:"mem_total"`
	AgentVersion string    `json:"agent_version"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Online       bool      `json:"online"`
	// Latest headline numbers for list views.
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float64 `json:"mem_percent"`
}

// HistoryPoint is one downsampled point in a time-series query.
type HistoryPoint struct {
	Timestamp  int64   `json:"ts"`
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float64 `json:"mem_percent"`
	MemUsed    uint64  `json:"mem_used"`
	RxRate     float64 `json:"rx_rate_bps"`
	TxRate     float64 `json:"tx_rate_bps"`
	DiskPct    float64 `json:"disk_percent"`
	MaxTemp    float64 `json:"max_temp_c"`
	IoReadBps  float64 `json:"io_read_bps"`
	IoWriteBps float64 `json:"io_write_bps"`
}
