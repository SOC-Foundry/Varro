package server

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// Default indicator feeds — abuse.ch Feodo Tracker lists active botnet C2
// server IPs, free and keyless. Each feed is a plaintext file of one IP per
// line with # comments.
var defaultThreatFeeds = []string{
	"https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
}

const (
	threatRefreshEvery = 6 * time.Hour
	// Re-alert the same (endpoint,indicator) pair at most this often, so a
	// persistent bad connection doesn't flood the event feed every sample.
	threatRealertAfter = 1 * time.Hour
)

// threatIntel holds the current known-bad IP set and recent-match dedup state.
type threatIntel struct {
	feeds []string

	mu       sync.RWMutex
	badIPs   map[string]bool
	loadedAt time.Time

	alertMu   sync.Mutex
	lastAlert map[string]time.Time // "endpoint|ip" -> when last emitted
}

func newThreatIntel(feeds []string) *threatIntel {
	if len(feeds) == 0 {
		feeds = defaultThreatFeeds
	}
	return &threatIntel{
		feeds:     feeds,
		badIPs:    map[string]bool{},
		lastAlert: map[string]time.Time{},
	}
}

// count returns how many indicators are loaded.
func (t *threatIntel) count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.badIPs)
}

func (t *threatIntel) isBad(ip string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.badIPs[ip]
}

// shouldAlert reports whether a fresh match for (endpoint,ip) should emit,
// rate-limiting repeats.
func (t *threatIntel) shouldAlert(endpointID, ip string) bool {
	key := endpointID + "|" + ip
	t.alertMu.Lock()
	defer t.alertMu.Unlock()
	if last, ok := t.lastAlert[key]; ok && time.Since(last) < threatRealertAfter {
		return false
	}
	t.lastAlert[key] = time.Now()
	return true
}

// refreshLoop fetches feeds now and every threatRefreshEvery.
func (s *Server) threatRefreshLoop(ctx context.Context) {
	for {
		s.ti.refresh(ctx, s.log)
		select {
		case <-ctx.Done():
			return
		case <-time.After(threatRefreshEvery):
		}
	}
}

func (t *threatIntel) refresh(ctx context.Context, log logger) {
	client := &http.Client{Timeout: 30 * time.Second}
	merged := map[string]bool{}
	for _, feed := range t.feeds {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Error("threat feed fetch failed", "feed", feed, "error", err)
			continue
		}
		n := 0
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Tolerate "ip,port,..." CSV rows as well as bare IPs.
			if i := strings.IndexAny(line, ",\t "); i > 0 {
				line = line[:i]
			}
			if net.ParseIP(line) != nil {
				merged[line] = true
				n++
			}
		}
		resp.Body.Close()
		log.Info("threat feed loaded", "feed", feed, "indicators", n)
	}
	// Only replace the set if at least one feed yielded data, so a transient
	// outage doesn't blank out protection.
	if len(merged) == 0 {
		return
	}
	t.mu.Lock()
	t.badIPs = merged
	t.loadedAt = time.Now()
	t.mu.Unlock()
}

// logger is the subset of slog we use (keeps the helper testable).
type logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

// checkThreats matches a snapshot's connections against the indicator set,
// emitting a rate-limited threat_match event per bad remote.
func (s *Server) checkThreats(ctx context.Context, orgID string, snap *model.Snapshot) {
	if s.ti == nil || s.ti.count() == 0 {
		return
	}
	for _, conn := range snap.Security.Connections {
		ip, _ := splitRemote(conn.Remote)
		if ip == "" || !s.ti.isBad(ip) {
			continue
		}
		if !s.ti.shouldAlert(snap.AgentID, ip) {
			continue
		}
		proc := conn.Process
		if proc == "" {
			proc = "unknown process"
		}
		msg := "THREAT: " + snap.Hostname + " (" + proc + ") connected to known-malicious IP " + ip +
			" — matches threat-intel feed"
		s.store.InsertServerEvent(ctx, orgID, snap.AgentID, model.EventThreatMatch, msg)
		s.log.Warn("threat-intel match", "endpoint", snap.Hostname, "ip", ip, "process", proc)
		s.notifyEvents(snap.Hostname, []model.Event{{Type: model.EventThreatMatch, Message: msg}})
	}
}
