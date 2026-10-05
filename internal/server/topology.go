package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// ipIndex maps IP address -> endpoint ID, built from reported interface
// addresses (authoritative) and each agent's observed ingest source address
// (fallback, which survives NAT between the endpoint and the collector).
type ipIndex struct {
	mu   sync.RWMutex
	byIP map[string]string
}

func newIPIndex() *ipIndex { return &ipIndex{byIP: map[string]string{}} }

func (x *ipIndex) set(ip, endpointID string) {
	if ip == "" || endpointID == "" {
		return
	}
	if p := net.ParseIP(ip); p == nil || p.IsLoopback() || p.IsLinkLocalUnicast() {
		return
	}
	x.mu.Lock()
	x.byIP[ip] = endpointID
	x.mu.Unlock()
}

func (x *ipIndex) lookup(ip string) string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.byIP[ip]
}

// listenerIndex tracks each endpoint's current listening ports so edge
// recording can tell client->service flows from their server-side mirrors.
type listenerIndex struct {
	mu     sync.RWMutex
	byNode map[string]map[int]bool
}

func newListenerIndex() *listenerIndex { return &listenerIndex{byNode: map[string]map[int]bool{}} }

func (l *listenerIndex) set(endpointID string, ports map[int]bool) {
	l.mu.Lock()
	l.byNode[endpointID] = ports
	l.mu.Unlock()
}

// listening reports whether the endpoint is known to listen on the port.
// Unknown endpoints (no snapshot seen yet this server lifetime) report false,
// which just defers edge recording by one sample interval.
func (l *listenerIndex) listening(endpointID string, port int) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.byNode[endpointID][port]
}

// splitRemote splits "ip:port" (IPv4) or "v6addr:port" (our agents format the
// address bare, so the port is everything after the last colon).
func splitRemote(remote string) (ip string, port int) {
	i := strings.LastIndexByte(remote, ':')
	if i < 0 {
		return remote, 0
	}
	ip = strings.Trim(remote[:i], "[]")
	for _, ch := range remote[i+1:] {
		if ch < '0' || ch > '9' {
			return ip, 0
		}
		port = port*10 + int(ch-'0')
	}
	return ip, port
}

// clientIP extracts the agent's apparent source address, preferring the
// reverse proxy's X-Forwarded-For.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// correlateEdges indexes the snapshot's addresses and records fleet-internal
// edges from its connection table, emitting events for first-seen paths.
//
// Direction normalization: every TCP session appears in BOTH endpoints'
// connection tables — the client side points at the service port, the server
// side points back at the client's ephemeral port. Only the client->service
// direction is recorded, recognized by the destination port being one the
// destination endpoint actually listens on.
func (s *Server) correlateEdges(r *http.Request, orgID string, snap *model.Snapshot) {
	for _, nic := range snap.Network.Interfaces {
		for _, addr := range nic.Addrs {
			s.ips.set(addr, snap.AgentID)
		}
	}
	s.ips.set(clientIP(r), snap.AgentID)
	ports := map[int]bool{}
	for _, lp := range snap.Security.ListeningPorts {
		ports[int(lp.Port)] = true
	}
	s.listeners.set(snap.AgentID, ports)

	ts := snap.Timestamp.Unix()
	for _, conn := range snap.Security.Connections {
		ip, port := splitRemote(conn.Remote)
		dst := s.ips.lookup(ip)
		if dst == "" || dst == snap.AgentID {
			continue
		}
		if !s.listeners.listening(dst, port) {
			continue // server-side mirror of a flow owned by the other end
		}
		process := conn.Process
		if process == "" {
			process = "unknown"
		}
		isNew, err := s.store.UpsertEdge(r.Context(), orgID, snap.AgentID, dst, process, port, ts)
		if err != nil {
			s.log.Error("edge upsert failed", "error", err)
			continue
		}
		if isNew {
			dstName := dst
			if eps, err := s.store.Endpoints(r.Context(), nil); err == nil {
				for _, ep := range eps {
					if ep.ID == dst {
						dstName = ep.Hostname
						break
					}
				}
			}
			msg := "new internal connection: " + snap.Hostname + " (" + process + ") -> " +
				dstName + " port " + itoa(port)
			if err := s.store.InsertServerEvent(r.Context(), orgID, snap.AgentID,
				model.EventConnNewInternal, msg); err == nil {
				s.log.Info("topology edge discovered", "msg", msg)
				s.notifyEvents(snap.Hostname, []model.Event{{Type: model.EventConnNewInternal, Message: msg}})
			}
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 && i > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// handleTopologyReset clears an org's learned edges (org admins and up); the
// graph re-learns from live traffic within one sampling interval. First-seen
// events will re-fire for still-active paths.
func (s *Server) handleTopologyReset(w http.ResponseWriter, r *http.Request) {
	org, err := s.store.OrgByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !s.orgAdminAuthorized(r, org.ID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	n, err := s.store.DeleteOrgEdges(r.Context(), org.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.Info("topology edges reset", "org", org.ID, "removed", n)
	writeJSON(w, map[string]any{"org_id": org.ID, "removed": n})
}

// nodeRisk fuses signals into a single node rating for the map: active
// threat/detection is critical; an internet-exposed listener combined with
// open vulnerabilities or failing posture is high (the CNAPP "exposed +
// unpatched" case).
func (s *Server) nodeRisk(ctx context.Context, ep model.EndpointSummary, snap *model.Snapshot, hot map[string]bool) (string, []string) {
	var reasons []string
	if hot[model.EventThreatMatch] || hot[model.EventMalwareMatch] {
		reasons = append(reasons, "active threat-intel/malware match")
	}
	if hot[model.EventDetection] {
		reasons = append(reasons, "behavioral detection fired")
	}
	if len(reasons) > 0 {
		return "critical", reasons
	}

	exposed := false
	if snap != nil {
		for _, lp := range snap.Security.ListeningPorts {
			if lp.Address == "0.0.0.0" || lp.Address == "::" || lp.Address == "" {
				exposed = true
				break
			}
		}
	}
	vulns, _ := s.store.VulnCount(ctx, ep.ID)
	postureFails := 0
	if snap != nil {
		for _, p := range snap.Posture {
			if p.Status == model.PostureFail {
				postureFails++
			}
		}
	}
	if exposed && (vulns > 0 || postureFails > 0) {
		if vulns > 0 {
			reasons = append(reasons, fmt.Sprintf("internet-exposed listener + %d known vulns", vulns))
		}
		if postureFails > 0 {
			reasons = append(reasons, fmt.Sprintf("internet-exposed listener + %d posture failures", postureFails))
		}
		return "high", reasons
	}
	if vulns > 10 || postureFails > 2 {
		return "warn", []string{fmt.Sprintf("%d vulns, %d posture failures", vulns, postureFails)}
	}
	return "", nil
}

// handleTopology returns the org-scoped communication graph: fleet nodes, an
// "internet" node, internal edges from the edges table, and per-endpoint
// external aggregates from the latest snapshots.
func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	minutes := 60
	if m := r.URL.Query().Get("minutes"); m != "" {
		if v, err := time.ParseDuration(m + "m"); err == nil && v > 0 {
			minutes = int(v.Minutes())
		}
	}
	since := time.Now().Add(-time.Duration(minutes) * time.Minute)

	eps, err := s.store.Endpoints(r.Context(), scope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	inScope := map[string]bool{}
	fleetIPs := map[string]bool{}
	for _, ep := range eps {
		inScope[ep.ID] = true
	}

	edges, err := s.store.Edges(r.Context(), scope, since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Keep only edges where both ends are visible in this scope.
	kept := edges[:0]
	for _, e := range edges {
		if inScope[e.Src] && inScope[e.Dst] {
			kept = append(kept, e)
		}
	}
	edges = kept

	// External aggregates from latest snapshots; also collect fleet IPs so
	// internal traffic isn't double-counted as external.
	type extAgg struct {
		count   int
		bytes   uint64
		remotes map[string]int
	}
	ext := map[string]*extAgg{}
	snaps := map[string]*model.Snapshot{}
	for _, ep := range eps {
		if snap, err := s.store.Latest(r.Context(), ep.ID); err == nil && snap != nil {
			snaps[ep.ID] = snap
			for _, nic := range snap.Network.Interfaces {
				for _, a := range nic.Addrs {
					fleetIPs[a] = true
				}
			}
		}
	}
	for id, snap := range snaps {
		for _, conn := range snap.Security.Connections {
			ip, _ := splitRemote(conn.Remote)
			if ip == "" || fleetIPs[ip] || s.ips.lookup(ip) != "" {
				continue
			}
			if p := net.ParseIP(ip); p == nil || p.IsLoopback() {
				continue
			}
			a := ext[id]
			if a == nil {
				a = &extAgg{remotes: map[string]int{}}
				ext[id] = a
			}
			a.count++
			a.remotes[ip]++
		}
		// conntrack byte totals toward non-fleet remotes give the edge weight.
		for _, fl := range snap.Network.Flows {
			ip, _ := splitRemote(fl.Remote)
			if ip == "" || fleetIPs[ip] || s.ips.lookup(ip) != "" {
				continue
			}
			if p := net.ParseIP(ip); p == nil || p.IsLoopback() {
				continue
			}
			a := ext[id]
			if a == nil {
				a = &extAgg{remotes: map[string]int{}}
				ext[id] = a
			}
			a.bytes += fl.BytesOut + fl.BytesIn
			if a.remotes[ip] == 0 {
				a.remotes[ip] = 1 // ensure flow-only remotes still surface
			}
		}
	}
	// Recent high-signal events per endpoint → "critical" node risk.
	hotByEndpoint := map[string]map[string]bool{}
	if evs, err := s.store.Events(r.Context(), "", scope, 500); err == nil {
		for _, ev := range evs {
			switch ev.Type {
			case model.EventDetection, model.EventThreatMatch, model.EventMalwareMatch:
				if hotByEndpoint[ev.EndpointID] == nil {
					hotByEndpoint[ev.EndpointID] = map[string]bool{}
				}
				hotByEndpoint[ev.EndpointID][ev.Type] = true
			}
		}
	}

	// Build enriched fleet nodes.
	nodes := make([]model.TopoNode, 0, len(eps)+1)
	for _, ep := range eps {
		n := model.TopoNode{ID: ep.ID, Hostname: ep.Hostname, Online: ep.Online, Platform: ep.Platform}
		snap := snaps[ep.ID]
		if snap != nil {
			n.Containers = len(snap.Containers)
			if c := snap.Host.Cloud; c != nil {
				n.Group = c.Provider + "/" + c.AccountID
				if c.Region != "" {
					n.Group += "/" + c.Region
				}
			}
		}
		n.Risk, n.RiskReasons = s.nodeRisk(r.Context(), ep, snap, hotByEndpoint[ep.ID])
		nodes = append(nodes, n)
	}

	if len(ext) > 0 {
		nodes = append(nodes, model.TopoNode{ID: "internet", Hostname: "internet", Online: true})
		for id, a := range ext {
			type rc struct {
				ip string
				n  int
			}
			var rcs []rc
			for ip, n := range a.remotes {
				rcs = append(rcs, rc{ip, n})
			}
			sort.Slice(rcs, func(i, j int) bool { return rcs[i].n > rcs[j].n })
			var remotes, names, geo []string
			malicious := false
			for i := 0; i < len(rcs) && i < 5; i++ {
				remotes = append(remotes, rcs[i].ip)
				names = append(names, s.rdns.name(rcs[i].ip))
				if s.geo != nil {
					geo = append(geo, s.geo.label(rcs[i].ip))
				}
			}
			// Flag the edge if any remote (not just the top 5) is known-bad.
			if s.ti != nil {
				for ip := range a.remotes {
					if s.ti.isBad(ip) {
						malicious = true
						break
					}
				}
			}
			edges = append(edges, model.TopoEdge{
				Src: id, Dst: "internet", Count: a.count, Bytes: a.bytes,
				Remotes: remotes, RemoteNames: names, RemoteGeo: geo, Malicious: malicious,
			})
		}
	}

	if edges == nil {
		edges = []model.TopoEdge{}
	}
	writeJSON(w, map[string]any{"nodes": nodes, "edges": edges, "window_minutes": minutes})
}
