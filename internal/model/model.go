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
	EventProcessNew      = "process_new"
	EventListenNew       = "listen_new"
	EventNICNew          = "nic_new"
	EventAutostartChange = "autostart_change"
	EventUserLogin       = "user_login"
	EventAuthFailures    = "auth_failures"
	EventIdentityChange  = "identity_change" // passwd/group/sudoers/authorized_keys
	EventSUIDChange      = "suid_change"
	EventPkgInstall      = "pkg_install"
	EventPkgRemove       = "pkg_remove"
	EventPkgUpgrade      = "pkg_upgrade"
	EventPostureChange   = "posture_change"
	EventServiceFailed   = "service_failed"
	EventRebootRequired  = "reboot_required"
	EventFIMChange       = "fim_change"
	EventConnNewInternal = "conn_new_internal" // first-seen fleet-internal communication path
	EventVulnNew         = "vuln_new"          // package newly matched to a known vulnerability
	EventThreatMatch     = "threat_match"      // connection to a known-malicious indicator
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
}

type EdgeProcess struct {
	Process string `json:"process"`
	Port    int    `json:"port"`
}

type TopoEdge struct {
	Src       string        `json:"src"`
	Dst       string        `json:"dst"` // endpoint ID, or "internet"
	Internal  bool          `json:"internal"`
	Processes []EdgeProcess `json:"processes"`
	Count     int           `json:"count"` // external: connection count; internal: process/port pairs
	FirstSeen time.Time     `json:"first_seen,omitempty"`
	LastSeen  time.Time     `json:"last_seen,omitempty"`
	Remotes   []string      `json:"remotes,omitempty"`        // external edges: sample remote IPs
	RemoteNames []string    `json:"remote_names,omitempty"`   // reverse-DNS of Remotes, same order ("" when unresolved)
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
}

// HostInfo describes the endpoint itself; it changes rarely.
type HostInfo struct {
	OS              string `json:"os"`
	Platform        string `json:"platform"`
	PlatformVersion string `json:"platform_version"`
	KernelVersion   string `json:"kernel_version"`
	Arch            string `json:"arch"`
	Uptime          uint64 `json:"uptime_seconds"`
	BootTime        int64  `json:"boot_time"`
	NumProcs        uint64 `json:"num_procs"`
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
}

type InterfaceStats struct {
	Name        string   `json:"name"`
	Addrs       []string `json:"addrs,omitempty"` // non-loopback, non-link-local IPs
	BytesSent   uint64   `json:"bytes_sent"`
	BytesRecv   uint64   `json:"bytes_recv"`
	PacketsSent uint64  `json:"packets_sent"`
	PacketsRecv uint64  `json:"packets_recv"`
	ErrIn       uint64  `json:"err_in"`
	ErrOut      uint64  `json:"err_out"`
	RxRate      float64 `json:"rx_rate_bps"` // computed from deltas, 0 on first sample
	TxRate      float64 `json:"tx_rate_bps"`
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
	AutoJoinDomain string    `json:"auto_join_domain,omitempty"`
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

// OrgTokenInfo describes an enrollment token without revealing it.
type OrgTokenInfo struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
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
