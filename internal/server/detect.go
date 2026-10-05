package server

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// Behavioral detection: correlation rules over a snapshot's exec stream,
// connections, listeners, and resource use. Unlike IOC matching (known-bad
// IPs/hashes), these fire on *patterns of behavior* — the EDR-class signal.

// Process-name sets. Shells and raw network tools are the high-signal ones:
// a bash or nc with a live socket, or listening, is rarely benign.
var (
	shellTools = set("sh", "bash", "zsh", "dash", "ash", "ksh", "nc", "ncat", "netcat", "socat")
	miners     = set("xmrig", "minerd", "cpuminer", "xmr-stak", "cgminer", "ethminer",
		"nbminer", "phoenixminer", "kdevtmpfsi", "kinsing", "xmr")
	reconTools   = set("nmap", "masscan", "zmap", "nikto", "hydra", "sqlmap")
	miningPorts  = set("3333", "3334", "4444", "5555", "7777", "8333", "14444", "45700")
	execStormMin = 80 // distinct execs in one ~10s sample
)

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

// base name without path/args, lowercased.
func baseComm(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexByte(s, ' '); i >= 0 {
		s = s[:i]
	}
	return s
}

// detector rate-limits repeat detections per (endpoint, rule, key).
type detector struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func newDetector() *detector { return &detector{last: map[string]time.Time{}} }

func (d *detector) should(endpoint, rule, key string) bool {
	k := endpoint + "|" + rule + "|" + key
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.last[k]; ok && time.Since(t) < time.Hour {
		return false
	}
	d.last[k] = time.Now()
	return true
}

// detect evaluates behavioral rules and emits detection events.
func (s *Server) detect(ctx context.Context, orgID string, snap *model.Snapshot) {
	fire := func(rule, severity, key, msg string) {
		if !s.det.should(snap.AgentID, rule, key) {
			return
		}
		full := fmt.Sprintf("[%s] %s: %s", severity, rule, msg)
		s.store.InsertServerEvent(ctx, orgID, snap.AgentID, model.EventDetection, full)
		s.log.Warn("behavioral detection", "rule", rule, "severity", severity,
			"endpoint", snap.Hostname, "detail", msg)
		s.notifyEvents(snap.Hostname, []model.Event{{Type: model.EventDetection, Message: full}})
	}

	// 1. Reverse shell / C2: a shell or raw network tool with a live outbound
	//    connection.
	for _, c := range snap.Security.Connections {
		if shellTools[baseComm(c.Process)] {
			fire("reverse_shell", "HIGH", c.Process+c.Remote,
				snap.Hostname+": "+c.Process+" has an active connection to "+c.Remote+
					" (shell/network tool with a live socket — possible reverse shell)")
		}
	}

	// 2. Backdoor listener: a shell or network tool bound to a port.
	for _, lp := range snap.Security.ListeningPorts {
		if shellTools[baseComm(lp.Process)] {
			fire("shell_listener", "HIGH", lp.Process+itoa(int(lp.Port)),
				fmt.Sprintf("%s: %s is listening on %s:%d (interactive shell/tool as a listener — possible backdoor)",
					snap.Hostname, lp.Process, lp.Address, lp.Port))
		}
	}

	// 3. Crypto miner: known miner binary, or pegged CPU talking to a pool port.
	for _, e := range snap.Execs {
		if miners[baseComm(e.Comm)] {
			fire("crypto_miner", "HIGH", e.Comm,
				snap.Hostname+": executed known mining tool "+e.Comm)
		}
	}
	for _, p := range snap.Processes {
		if miners[baseComm(p.Name)] {
			fire("crypto_miner", "HIGH", p.Name,
				snap.Hostname+": known mining process "+p.Name+" running")
		}
	}
	if snap.CPU.TotalPercent > 90 {
		for _, c := range snap.Security.Connections {
			_, port := splitRemote(c.Remote)
			if miningPorts[itoa(port)] {
				fire("crypto_miner", "MEDIUM", c.Remote,
					fmt.Sprintf("%s: sustained %.0f%% CPU with a connection to mining-pool port %s",
						snap.Hostname, snap.CPU.TotalPercent, c.Remote))
			}
		}
	}

	// 4. Recon tooling.
	for _, e := range snap.Execs {
		if reconTools[baseComm(e.Comm)] {
			fire("recon_tool", "MEDIUM", e.Comm,
				snap.Hostname+": network reconnaissance tool "+e.Comm+" executed")
		}
	}

	// 5. Exec storm: an abnormal burst of distinct execs in one interval.
	if len(snap.Execs) >= execStormMin {
		fire("exec_storm", "MEDIUM", "",
			fmt.Sprintf("%s: %d distinct process execs in one interval (possible fork/exec flood or mass activity)",
				snap.Hostname, len(snap.Execs)))
	}
}
