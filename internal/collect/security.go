package collect

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/shirou/gopsutil/v4/host"
	gnet "github.com/shirou/gopsutil/v4/net"

	"github.com/soc-foundry/varro/internal/model"
)

// Per-sample event caps keep a noisy endpoint (or a deliberate flood) from
// bloating snapshots.
const (
	maxProcessEvents   = 15
	maxListenEvents    = 10
	maxAutostartEvents = 20
)

// Linux auth logs, tried in order; the first readable one is used.
var authLogPaths = []string{"/var/log/auth.log", "/var/log/secure"}

// Filesystem locations where persistence is commonly established. Watched as
// a flat (path -> size/mtime) fingerprint; any add/modify/remove is an event.
func autostartRoots() []string {
	roots := []string{
		"/etc/systemd/system",
		"/etc/init.d",
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/crontab",
		"/etc/rc.local",
	}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, ".config", "autostart"))
	}
	return roots
}

// sampleSecurity fills snap.Security and appends diff events. pidNames maps
// PID to process name from this sample's process scan.
func (c *Collector) sampleSecurity(ctx context.Context, snap *model.Snapshot, pidNames map[int32]string) {
	c.sampleConnections(ctx, snap, pidNames)
	c.sampleSessions(ctx, snap)
	c.sampleAuthLog(snap)
	c.sampleAutostart(snap)
}

func (c *Collector) sampleConnections(ctx context.Context, snap *model.Snapshot, pidNames map[int32]string) {
	conns, err := gnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, cn := range conns {
		switch {
		case cn.Status == "ESTABLISHED":
			snap.Security.EstablishedConns++
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
