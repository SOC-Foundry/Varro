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

// Default malware-hash feed — abuse.ch MalwareBazaar recent SHA-256 export
// (plaintext, one hash per line). The full corpus is millions of hashes and
// would exhaust a small collector's memory; the recent export stays bounded.
var defaultHashFeeds = []string{
	"https://bazaar.abuse.ch/export/txt/sha256/recent/",
}

const (
	threatRefreshEvery = 6 * time.Hour
	// Re-alert the same (endpoint,indicator) pair at most this often, so a
	// persistent bad connection doesn't flood the event feed every sample.
	threatRealertAfter = 1 * time.Hour
)

// threatIntel holds known-bad IP and malware-hash sets plus match dedup state.
type threatIntel struct {
	feeds     []string
	hashFeeds []string

	mu       sync.RWMutex
	badIPs   map[string]bool
	badHash  map[string]bool
	loadedAt time.Time

	alertMu   sync.Mutex
	lastAlert map[string]time.Time // "endpoint|indicator" -> when last emitted
}

func newThreatIntel(feeds, hashFeeds []string) *threatIntel {
	if len(feeds) == 0 {
		feeds = defaultThreatFeeds
	}
	if len(hashFeeds) == 0 {
		hashFeeds = defaultHashFeeds
	}
	return &threatIntel{
		feeds:     feeds,
		hashFeeds: hashFeeds,
		badIPs:    map[string]bool{},
		badHash:   map[string]bool{},
		lastAlert: map[string]time.Time{},
	}
}

// count returns how many IP indicators are loaded.
func (t *threatIntel) count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.badIPs)
}

// hashCount returns how many malware-hash indicators are loaded.
func (t *threatIntel) hashCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.badHash)
}

func (t *threatIntel) isBad(ip string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.badIPs[ip]
}

func (t *threatIntel) isBadHash(h string) bool {
	if h == "" {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.badHash[strings.ToLower(h)]
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
	// Malware-hash feeds (sha256 per line).
	hashes := map[string]bool{}
	for _, feed := range t.hashFeeds {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Error("hash feed fetch failed", "feed", feed, "error", err)
			continue
		}
		n := 0
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if i := strings.IndexAny(line, ",\t "); i > 0 {
				line = line[:i]
			}
			line = strings.Trim(strings.ToLower(line), `"`)
			if len(line) == 64 && isHex(line) {
				hashes[line] = true
				n++
			}
		}
		resp.Body.Close()
		log.Info("hash feed loaded", "feed", feed, "indicators", n)
	}

	// Only replace a set if its feeds yielded data, so a transient outage
	// doesn't blank out protection.
	t.mu.Lock()
	if len(merged) > 0 {
		t.badIPs = merged
	}
	if len(hashes) > 0 {
		t.badHash = hashes
	}
	t.loadedAt = time.Now()
	t.mu.Unlock()
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// logger is the subset of slog we use (keeps the helper testable).
type logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

// checkThreats matches a snapshot's connections against the known-bad IP set
// and its new-process hashes against the malware-hash set, emitting
// rate-limited events per match.
func (s *Server) checkThreats(ctx context.Context, orgID string, snap *model.Snapshot) {
	if s.ti == nil {
		return
	}
	for _, conn := range snap.Security.Connections {
		ip, _ := splitRemote(conn.Remote)
		if ip == "" || !s.ti.isBad(ip) || !s.ti.shouldAlert(snap.AgentID, ip) {
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
	for _, ph := range snap.ProcHashes {
		if !s.ti.isBadHash(ph.SHA256) || !s.ti.shouldAlert(snap.AgentID, ph.SHA256) {
			continue
		}
		msg := "MALWARE: " + snap.Hostname + " ran " + ph.Name + " (pid " + itoa(int(ph.PID)) +
			") whose binary sha256 " + ph.SHA256 + " matches a known-malware feed"
		s.store.InsertServerEvent(ctx, orgID, snap.AgentID, model.EventMalwareMatch, msg)
		s.log.Warn("malware-hash match", "endpoint", snap.Hostname, "process", ph.Name, "sha256", ph.SHA256)
		s.notifyEvents(snap.Hostname, []model.Event{{Type: model.EventMalwareMatch, Message: msg}})
	}
}
