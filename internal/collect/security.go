package collect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/soc-foundry/varro/internal/model"
)

// maxHashableBinary bounds how large an executable we are willing to hash for
// a new-process event.
const maxHashableBinary = 256 << 20

// hashProcessBinary returns the sha256 of a process's executable, or "" when
// it cannot be read (exited, permission, deleted binary, too large).
func hashProcessBinary(pid int32) string {
	p, err := process.NewProcess(pid)
	if err != nil {
		return ""
	}
	path, err := p.Exe()
	if err != nil || path == "" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxHashableBinary {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Per-sample event caps keep a noisy endpoint (or a deliberate flood) from
// bloating snapshots.
const (
	maxProcessEvents   = 15
	maxListenEvents    = 10
	maxAutostartEvents = 20
	maxIdentityEvents  = 20
	maxSUIDEvents      = 20
	maxConnections     = 50

	suidScanEvery = 5 * time.Minute
)

// Linux auth logs, tried in order; the first readable one is used. (Absent on
// other platforms; the auth-log collector then reports nothing.)
var authLogPaths = []string{"/var/log/auth.log", "/var/log/secure"}

// sampleSecurity fills snap.Security and appends diff events. pidNames maps
// PID to process name from this sample's process scan.
func (c *Collector) sampleSecurity(ctx context.Context, snap *model.Snapshot, pidNames map[int32]string) {
	c.sampleConnections(ctx, snap, pidNames)
	c.sampleSessions(ctx, snap)
	c.sampleAuthLog(snap)
	c.sampleAutostart(snap)
	c.sampleIdentityFiles(snap)
	c.sampleSUID(snap)
}

func (c *Collector) sampleConnections(ctx context.Context, snap *model.Snapshot, pidNames map[int32]string) {
	conns, err := gnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return
	}
	seen := map[string]bool{}
	connSeen := map[string]bool{}
	for _, cn := range conns {
		switch {
		case cn.Status == "ESTABLISHED":
			snap.Security.EstablishedConns++
			// Machine-local connections are noise for a fleet view.
			if ip := net.ParseIP(cn.Raddr.IP); ip != nil && ip.IsLoopback() {
				continue
			}
			// Attributed connection table, deduped by (remote, pid), capped.
			remote := fmt.Sprintf("%s:%d", cn.Raddr.IP, cn.Raddr.Port)
			key := fmt.Sprintf("%s/%d", remote, cn.Pid)
			if !connSeen[key] && len(snap.Security.Connections) < maxConnections {
				connSeen[key] = true
				snap.Security.Connections = append(snap.Security.Connections, model.OutboundConn{
					Proto:   "tcp",
					Local:   fmt.Sprintf("%s:%d", cn.Laddr.IP, cn.Laddr.Port),
					Remote:  remote,
					PID:     cn.Pid,
					Process: pidNames[cn.Pid],
				})
			}
		case cn.Status == "LISTEN" || (cn.Type == 2 && cn.Raddr.Port == 0):
			proto := "tcp"
			if cn.Type == 2 {
				proto = "udp"
			}
			key := fmt.Sprintf("%s:%s:%d", proto, cn.Laddr.IP, cn.Laddr.Port)
			if seen[key] {
				continue
			}
			seen[key] = true
			snap.Security.ListeningPorts = append(snap.Security.ListeningPorts, model.ListeningPort{
				Proto:   proto,
				Address: cn.Laddr.IP,
				Port:    cn.Laddr.Port,
				PID:     cn.Pid,
				Process: pidNames[cn.Pid],
			})
		}
	}
	sort.Slice(snap.Security.ListeningPorts, func(i, j int) bool {
		return snap.Security.ListeningPorts[i].Port < snap.Security.ListeningPorts[j].Port
	})

	// Diff against the previous sample's listener set.
	if c.prevPorts != nil {
		n := 0
		for key := range seen {
			if !c.prevPorts[key] && n < maxListenEvents {
				snap.Events = append(snap.Events, model.Event{
					Type:    model.EventListenNew,
					Message: "new listening socket " + key + " (" + portProcess(snap.Security.ListeningPorts, key) + ")",
				})
				n++
			}
		}
	}
	c.prevPorts = seen
}

func portProcess(ports []model.ListeningPort, key string) string {
	for _, p := range ports {
		if fmt.Sprintf("%s:%s:%d", p.Proto, p.Address, p.Port) == key && p.Process != "" {
			return p.Process
		}
	}
	return "unknown process"
}

func (c *Collector) sampleSessions(ctx context.Context, snap *model.Snapshot) {
	users, err := host.UsersWithContext(ctx)
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, u := range users {
		snap.Security.Sessions = append(snap.Security.Sessions, model.SessionInfo{
			User:     u.User,
			Terminal: u.Terminal,
			Host:     u.Host,
			Started:  int64(u.Started),
		})
		key := u.User + "@" + u.Terminal
		seen[key] = true
		if c.prevSessions != nil && !c.prevSessions[key] {
			msg := "user session started: " + key
			if u.Host != "" {
				msg += " from " + u.Host
			}
			snap.Events = append(snap.Events, model.Event{Type: model.EventUserLogin, Message: msg})
		}
	}
	c.prevSessions = seen
}

// sampleAuthLog counts failed-authentication lines appended to the auth log
// since the previous sample. Best effort: silently reports 0 when no log is
// readable (e.g. journald-only systems or an unprivileged agent).
func (c *Collector) sampleAuthLog(snap *model.Snapshot) {
	if c.authLogPath == "" {
		for _, p := range authLogPaths {
			if f, err := os.Open(p); err == nil {
				st, err := f.Stat()
				f.Close()
				if err == nil {
					c.authLogPath = p
					c.authLogOffset = st.Size() // start counting from now
				}
				break
			}
		}
		return
	}

	f, err := os.Open(c.authLogPath)
	if err != nil {
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return
	}
	if st.Size() < c.authLogOffset {
		c.authLogOffset = 0 // rotated
	}
	if st.Size() == c.authLogOffset {
		return
	}
	if _, err := f.Seek(c.authLogOffset, io.SeekStart); err != nil {
		return
	}
	// New content is bounded per interval under normal operation; cap reads
	// at 4 MiB to stay safe under log floods.
	data, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return
	}
	c.authLogOffset += int64(len(data))

	count := bytes.Count(data, []byte("Failed password")) +
		bytes.Count(data, []byte("authentication failure"))
	snap.Security.FailedAuths = count
	if count > 0 {
		snap.Events = append(snap.Events, model.Event{
			Type:    model.EventAuthFailures,
			Message: fmt.Sprintf("%d failed authentication attempt(s) in %s", count, c.authLogPath),
		})
	}
}

func (c *Collector) sampleIdentityFiles(snap *model.Snapshot) {
	current := map[string]string{}
	for _, p := range identityPaths() {
		if info, err := os.Stat(p); err == nil {
			current[p] = fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
		}
	}
	if c.prevIdentity != nil {
		n := 0
		emit := func(verb, path string) {
			if n < maxIdentityEvents {
				snap.Events = append(snap.Events, model.Event{
					Type:    model.EventIdentityChange,
					Message: "identity file " + verb + ": " + path,
				})
				n++
			}
		}
		for p, fp := range current {
			if prev, ok := c.prevIdentity[p]; !ok {
				emit("created", p)
			} else if prev != fp {
				emit("modified", p)
			}
		}
		for p := range c.prevIdentity {
			if _, ok := current[p]; !ok {
				emit("removed", p)
			}
		}
	}
	c.prevIdentity = current
}

// suidDirs are scanned for setuid binaries; a new one appearing is a classic
// privilege-escalation persistence trick. (Empty-result no-op on Windows.)
var suidDirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"}

func (c *Collector) sampleSUID(snap *model.Snapshot) {
	if runtime.GOOS == "windows" {
		return
	}
	if !c.lastSUIDScan.IsZero() && time.Since(c.lastSUIDScan) < suidScanEvery {
		return
	}
	c.lastSUIDScan = time.Now()

	current := map[string]bool{}
	for _, dir := range suidDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			info, err := e.Info()
			if err != nil || info.IsDir() {
				continue
			}
			if info.Mode()&os.ModeSetuid != 0 {
				current[filepath.Join(dir, e.Name())] = true
			}
		}
	}
	if c.suidSet != nil {
		n := 0
		for p := range current {
			if !c.suidSet[p] && n < maxSUIDEvents {
				snap.Events = append(snap.Events, model.Event{
					Type:    model.EventSUIDChange,
					Message: "new setuid binary: " + p,
				})
				n++
			}
		}
		for p := range c.suidSet {
			if !current[p] && n < maxSUIDEvents {
				snap.Events = append(snap.Events, model.Event{
					Type:    model.EventSUIDChange,
					Message: "setuid binary removed: " + p,
				})
				n++
			}
		}
	}
	c.suidSet = current
}

func (c *Collector) sampleAutostart(snap *model.Snapshot) {
	current := map[string]string{}
	for _, root := range autostartRoots() {
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d == nil || d.IsDir() {
				return nil
			}
			if info, err := d.Info(); err == nil {
				current[path] = fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
			}
			return nil
		})
	}
	// Platform-specific persistence locations that aren't plain files (e.g.
	// Windows registry Run keys).
	for k, v := range platformAutostartExtras() {
		current[k] = v
	}

	if c.prevAutostart != nil {
		n := 0
		emit := func(verb, path string) {
			if n < maxAutostartEvents {
				snap.Events = append(snap.Events, model.Event{
					Type:    model.EventAutostartChange,
					Message: "autostart " + verb + ": " + path,
				})
				n++
			}
		}
		for path, fp := range current {
			prev, ok := c.prevAutostart[path]
			if !ok {
				emit("entry added", path)
			} else if prev != fp {
				emit("entry modified", path)
			}
		}
		for path := range c.prevAutostart {
			if _, ok := current[path]; !ok {
				emit("entry removed", path)
			}
		}
	}
	c.prevAutostart = current
}
