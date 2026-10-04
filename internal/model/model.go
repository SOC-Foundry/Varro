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
	Proto   string `json:"proto"`
	Local   string `json:"local"`
	Remote  string `json:"remote"`
	PID     int32  `json:"pid"`
	Process string `json:"process"`
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
)

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
	Name        string  `json:"name"`
	BytesSent   uint64  `json:"bytes_sent"`
	BytesRecv   uint64  `json:"bytes_recv"`
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
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// User is a dashboard user authenticated via Google sign-in.
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Admin bool   `json:"admin"` // instance admin: sees all orgs, manages orgs/tokens
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
