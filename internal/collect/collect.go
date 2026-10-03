// Package collect gathers hardware and OS telemetry from the local machine
// using gopsutil.
package collect

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/soc-foundry/varro/internal/model"
)

const topProcesses = 30

// Collector samples the local machine. It keeps previous-sample state (network
// counters, process/listener/session sets, autostart fingerprints) to compute
// rates and emit change events, so a single Collector must be reused across
// samples.
type Collector struct {
	agentID string
	version string

	prevNetTime time.Time
	prevRx      uint64
	prevTx      uint64

	prevProcs     map[int32]string  // pid -> name
	prevNICs      map[string]bool   // interface names
	prevPorts     map[string]bool   // proto:addr:port
	prevSessions  map[string]bool   // user@terminal
	prevAutostart map[string]string // path -> size:mtime fingerprint
	authLogPath   string
	authLogOffset int64
}

// New builds a Collector. The agent ID is the stable host ID when available,
// falling back to the hostname.
func New(ctx context.Context, version string) (*Collector, error) {
	info, err := host.InfoWithContext(ctx)
	if err != nil {
		return nil, err
	}
	id := info.HostID
	if id == "" {
		id = info.Hostname
	}
	return &Collector{agentID: id, version: version}, nil
}

func (c *Collector) AgentID() string { return c.agentID }

// Sample gathers one full snapshot. Individual collector failures (e.g. a
// permission-denied process) are tolerated; the snapshot carries whatever
// could be read.
func (c *Collector) Sample(ctx context.Context) (*model.Snapshot, error) {
	now := time.Now().UTC()
	snap := &model.Snapshot{
		AgentID:      c.agentID,
		AgentVersion: c.version,
		Timestamp:    now,
	}

	if info, err := host.InfoWithContext(ctx); err == nil {
		snap.Hostname = info.Hostname
		snap.Host = model.HostInfo{
			OS:              info.OS,
			Platform:        info.Platform,
			PlatformVersion: info.PlatformVersion,
			KernelVersion:   info.KernelVersion,
			Arch:            runtime.GOARCH,
			Uptime:          info.Uptime,
			BootTime:        int64(info.BootTime),
			NumProcs:        info.Procs,
		}
	}

	c.sampleCPU(ctx, snap)
	c.sampleMemory(ctx, snap)
	c.sampleDisks(ctx, snap)
	c.sampleNetwork(ctx, now, snap)
	pidNames := c.sampleProcesses(ctx, snap)
	c.sampleSecurity(ctx, snap, pidNames)

	return snap, nil
}

func (c *Collector) sampleCPU(ctx context.Context, snap *model.Snapshot) {
	// Interval 0 means "since the previous call", which is what we want for
	// a long-lived collector; the very first sample reads since boot.
	if perCore, err := cpu.PercentWithContext(ctx, 0, true); err == nil {
		snap.CPU.PerCore = perCore
		var sum float64
		for _, p := range perCore {
			sum += p
		}
		if len(perCore) > 0 {
			snap.CPU.TotalPercent = sum / float64(len(perCore))
		}
		snap.CPU.Cores = len(perCore)
	}
	if avg, err := load.AvgWithContext(ctx); err == nil {
		snap.CPU.Load1 = avg.Load1
		snap.CPU.Load5 = avg.Load5
		snap.CPU.Load15 = avg.Load15
	}
}

func (c *Collector) sampleMemory(ctx context.Context, snap *model.Snapshot) {
	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		snap.Memory.Total = vm.Total
		snap.Memory.Used = vm.Used
		snap.Memory.Available = vm.Available
		snap.Memory.UsedPercent = vm.UsedPercent
	}
	if sw, err := mem.SwapMemoryWithContext(ctx); err == nil {
		snap.Memory.SwapTotal = sw.Total
		snap.Memory.SwapUsed = sw.Used
	}
}

func (c *Collector) sampleDisks(ctx context.Context, snap *model.Snapshot) {
	parts, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		return
	}
	for _, p := range parts {
		usage, err := disk.UsageWithContext(ctx, p.Mountpoint)
		if err != nil || usage.Total == 0 {
			continue
		}
		snap.Disks = append(snap.Disks, model.DiskMetrics{
			Mountpoint:  p.Mountpoint,
			Fstype:      p.Fstype,
			Total:       usage.Total,
			Used:        usage.Used,
			UsedPercent: usage.UsedPercent,
		})
	}
}

func (c *Collector) sampleNetwork(ctx context.Context, now time.Time, snap *model.Snapshot) {
	// Per-interface counters.
	perNIC, err := gnet.IOCountersWithContext(ctx, true)
	if err != nil {
		return
	}
	for _, nic := range perNIC {
		if nic.Name == "lo" {
			continue
		}
		snap.Network.Interfaces = append(snap.Network.Interfaces, model.InterfaceStats{
			Name:        nic.Name,
			BytesSent:   nic.BytesSent,
			BytesRecv:   nic.BytesRecv,
			PacketsSent: nic.PacketsSent,
			PacketsRecv: nic.PacketsRecv,
			ErrIn:       nic.Errin,
			ErrOut:      nic.Errout,
		})
	}

	// New-interface events (a NIC appearing on a server is worth noticing).
	nics := map[string]bool{}
	for _, s := range snap.Network.Interfaces {
		nics[s.Name] = true
		if c.prevNICs != nil && !c.prevNICs[s.Name] {
			snap.Events = append(snap.Events, model.Event{
				Type:    model.EventNICNew,
				Message: "new network interface: " + s.Name,
			})
		}
	}
	c.prevNICs = nics

	// Whole-host rates from counter deltas.
	var rx, tx uint64
	for _, s := range snap.Network.Interfaces {
		rx += s.BytesRecv
		tx += s.BytesSent
	}
	if !c.prevNetTime.IsZero() && rx >= c.prevRx && tx >= c.prevTx {
		dt := now.Sub(c.prevNetTime).Seconds()
		if dt > 0 {
			snap.Network.RxRate = float64(rx-c.prevRx) / dt
			snap.Network.TxRate = float64(tx-c.prevTx) / dt
		}
	}
	c.prevNetTime = now
	c.prevRx = rx
	c.prevTx = tx
}

// sampleProcesses fills the top-N process list, emits new-process events, and
// returns a pid -> name map covering every readable process (used to label
// listening sockets).
func (c *Collector) sampleProcesses(ctx context.Context, snap *model.Snapshot) map[int32]string {
	pidNames := map[int32]string{}
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return pidNames
	}
	infos := make([]model.ProcessInfo, 0, len(procs))
	newEvents := 0
	for _, p := range procs {
		// Each field read can fail independently (process exited, permission
		// denied); keep whatever we can get as long as there is a name.
		name, err := p.NameWithContext(ctx)
		if err != nil || name == "" {
			continue
		}
		info := model.ProcessInfo{PID: p.Pid, Name: name}
		if u, err := p.UsernameWithContext(ctx); err == nil {
			info.Username = u
		}
		if cp, err := p.CPUPercentWithContext(ctx); err == nil {
			info.CPUPercent = cp
		}
		if mp, err := p.MemoryPercentWithContext(ctx); err == nil {
			info.MemPercent = mp
		}
		if mi, err := p.MemoryInfoWithContext(ctx); err == nil && mi != nil {
			info.RSS = mi.RSS
		}
		if cl, err := p.CmdlineWithContext(ctx); err == nil {
			if len(cl) > 200 {
				cl = cl[:200]
			}
			info.Cmdline = cl
		}
		infos = append(infos, info)
		pidNames[p.Pid] = name

		// New-process event: a PID we did not see last sample. Kernel threads
		// (empty cmdline) are skipped as pure noise.
		if c.prevProcs != nil && info.Cmdline != "" {
			if _, seen := c.prevProcs[p.Pid]; !seen && newEvents < maxProcessEvents {
				msg := fmt.Sprintf("new process %s (pid %d", name, p.Pid)
				if info.Username != "" {
					msg += ", user " + info.Username
				}
				msg += "): " + info.Cmdline
				snap.Events = append(snap.Events, model.Event{Type: model.EventProcessNew, Message: msg})
				newEvents++
			}
		}
	}
	c.prevProcs = pidNames

	sort.Slice(infos, func(i, j int) bool {
		if infos[i].CPUPercent != infos[j].CPUPercent {
			return infos[i].CPUPercent > infos[j].CPUPercent
		}
		return infos[i].RSS > infos[j].RSS
	})
	if len(infos) > topProcesses {
		infos = infos[:topProcesses]
	}
	snap.Processes = infos
	return pidNames
}
