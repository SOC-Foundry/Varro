package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
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
				s.notifyEvents(orgID, snap.Hostname, []model.Event{{Type: model.EventConnNewInternal, Message: msg}})
			}
			// Dependency drift: if the source's config was parsed (it has resolvable
			// cross-host declared deps) but this new path isn't one of them, flag it —
			// an undeclared/shadow dependency or possible lateral movement.
			if undeclaredTarget(snap.DeclaredDeps, s.ips, dst) {
				dmsg := "undeclared dependency: " + snap.Hostname + " (" + process + ") -> " +
					dstName + " port " + itoa(port) + " — not in its configured dependencies"
				if err := s.store.InsertServerEvent(r.Context(), orgID, snap.AgentID,
					model.EventConnUndeclared, dmsg); err == nil {
					s.log.Warn("dependency drift", "msg", dmsg)
					s.notifyEvents(orgID, snap.Hostname, []model.Event{{Type: model.EventConnUndeclared, Message: dmsg}})
					s.siemForward(orgID, snap.Hostname, model.EventConnUndeclared, "LOW", "T1021 Remote Services", dmsg)
				}
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
	if hot[model.EventThreatMatch] || hot[model.EventMalwareMatch] || hot[model.EventDomainThreatMatch] {
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
	// Time-travel: ?at=<unix> returns the nearest stored historical snapshot.
	if at := r.URL.Query().Get("at"); at != "" {
		ts, _ := strconv.ParseInt(at, 10, 64)
		data, err := s.store.TopologyAt(r.Context(), scope, ts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if data == nil {
			http.Error(w, "no snapshot at that time", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}
	declared := r.URL.Query().Get("declared") == "1"
	nodes, edges, err := s.buildTopology(r.Context(), scope, minutes, declared)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"nodes": nodes, "edges": edges, "window_minutes": minutes, "declared": declared})
}

// handleTopologyTimeline returns the available historical-snapshot timestamps
// for the scope (per-org), for the time-travel slider.
func (s *Server) handleTopologyTimeline(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	ts, err := s.store.TopologyTimeline(r.Context(), scope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ts == nil {
		ts = []int64{}
	}
	writeJSON(w, map[string]any{"timestamps": ts})
}

// topoSnapshotLoop periodically serializes each org's topology for time-travel.
// Leader-only so multiple collectors don't duplicate snapshots.
func (s *Server) topoSnapshotLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !s.isLeader() {
				continue
			}
			orgs, err := s.store.Orgs(ctx)
			if err != nil {
				continue
			}
			now := time.Now().Unix()
			for _, org := range orgs {
				nodes, edges, err := s.buildTopology(ctx, []string{org.ID}, 60, false)
				if err != nil {
					continue
				}
				data, err := json.Marshal(map[string]any{
					"nodes": nodes, "edges": edges, "window_minutes": 60, "at": now,
				})
				if err != nil {
					continue
				}
				if err := s.store.SaveTopologySnapshot(ctx, org.ID, now, data); err != nil {
					s.log.Error("topology snapshot", "org", org.ID, "error", err)
				}
			}
			s.store.PruneTopologySnapshots(ctx, 7*24*time.Hour)
		}
	}
}

// buildTopology computes the node/edge graph for a scope over the trailing
// window. Shared by the live handler and the periodic time-travel snapshotter.
// resolveCalleeProcesses fills each internal edge's EdgeProcess.DstProcess from
// the destination endpoint's latest listening ports (port → listening process),
// turning "caller → host:port" into "caller → callee-app". Passive; mutates edges
// in place. External edges and ports with no known listener are left untouched.
func resolveCalleeProcesses(edges []model.TopoEdge, snaps map[string]*model.Snapshot) {
	listenProc := map[string]map[int]string{} // endpoint -> port -> listening process
	for id, snap := range snaps {
		if snap == nil {
			continue
		}
		m := map[int]string{}
		for _, lp := range snap.Security.ListeningPorts {
			if lp.Process != "" {
				m[int(lp.Port)] = lp.Process
			}
		}
		listenProc[id] = m
	}
	for i := range edges {
		e := &edges[i]
		if !e.Internal {
			continue
		}
		pm := listenProc[e.Dst]
		if pm == nil {
			continue
		}
		for j := range e.Processes {
			if proc := pm[e.Processes[j].Port]; proc != "" {
				e.Processes[j].DstProcess = proc
			}
		}
	}
}

func (s *Server) buildTopology(ctx context.Context, scope []string, minutes int, declared bool) ([]model.TopoNode, []model.TopoEdge, error) {
	since := time.Now().Add(-time.Duration(minutes) * time.Minute)

	eps, err := s.store.Endpoints(ctx, scope)
	if err != nil {
		return nil, nil, err
	}
	inScope := map[string]bool{}
	fleetIPs := map[string]bool{}
	for _, ep := range eps {
		inScope[ep.ID] = true
	}

	edges, err := s.store.Edges(ctx, scope, since)
	if err != nil {
		return nil, nil, err
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
	// internal traffic isn't double-counted as external. Per-remote stats let us
	// break external talk out into one node per destination domain.
	type remoteStat struct {
		count  int
		bytes  uint64
		domain string // agent-observed forward name (DNS/SNI), "" if unknown
	}
	type extAgg struct {
		remotes map[string]*remoteStat // remote IP -> stats
	}
	ext := map[string]*extAgg{}
	remoteOf := func(a *extAgg, ip string) *remoteStat {
		rs := a.remotes[ip]
		if rs == nil {
			rs = &remoteStat{}
			a.remotes[ip] = rs
		}
		return rs
	}
	snaps := map[string]*model.Snapshot{}
	for _, ep := range eps {
		if snap, err := s.store.Latest(ctx, ep.ID); err == nil && snap != nil {
			snaps[ep.ID] = snap
			for _, nic := range snap.Network.Interfaces {
				for _, a := range nic.Addrs {
					fleetIPs[a] = true
				}
			}
		}
	}

	// Resolve the callee process for each internal edge from the destination's
	// latest listening ports, so edges read app→app (e.g. nginx → postgres)
	// instead of app → host:port. Purely passive — the agent already reports each
	// listening port with its owning process. Self-heals from the latest snapshot.
	resolveCalleeProcesses(edges, snaps)
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
				a = &extAgg{remotes: map[string]*remoteStat{}}
				ext[id] = a
			}
			rs := remoteOf(a, ip)
			rs.count++
			if conn.Domain != "" {
				rs.domain = conn.Domain
			}
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
				a = &extAgg{remotes: map[string]*remoteStat{}}
				ext[id] = a
			}
			rs := remoteOf(a, ip)
			rs.bytes += fl.BytesOut + fl.BytesIn
			if fl.Domain != "" {
				rs.domain = fl.Domain
			}
			if rs.count == 0 {
				rs.count = 1 // ensure flow-only remotes still surface
			}
		}
		// eBPF-captured short-lived outbound connects — external destinations
		// the point-in-time connection scan may have missed.
		for _, cn := range snap.Conns {
			ip := cn.Dest
			if ip == "" || fleetIPs[ip] || s.ips.lookup(ip) != "" {
				continue
			}
			if p := net.ParseIP(ip); p == nil || p.IsLoopback() {
				continue
			}
			a := ext[id]
			if a == nil {
				a = &extAgg{remotes: map[string]*remoteStat{}}
				ext[id] = a
			}
			remoteOf(a, ip).count++
		}
	}
	// Recent high-signal events per endpoint → "critical" node risk. Keep the
	// actual messages (newest first, capped) so a critical node can explain
	// *why* it's critical, not just that it is.
	hotByEndpoint := map[string]map[string]bool{}
	hotMsgByEndpoint := map[string][]string{}
	hotMsgSeen := map[string]bool{} // endpoint|message, to dedupe repeats
	if evs, err := s.store.Events(ctx, "", scope, 500); err == nil {
		for _, ev := range evs {
			if ev.Timestamp.Before(since) {
				continue // "critical now" reflects the view window, not stale events
			}
			switch ev.Type {
			case model.EventDetection, model.EventThreatMatch, model.EventMalwareMatch, model.EventDomainThreatMatch:
				if hotByEndpoint[ev.EndpointID] == nil {
					hotByEndpoint[ev.EndpointID] = map[string]bool{}
				}
				hotByEndpoint[ev.EndpointID][ev.Type] = true
				key := ev.EndpointID + "|" + ev.Message
				if !hotMsgSeen[key] && len(hotMsgByEndpoint[ev.EndpointID]) < 3 {
					hotMsgSeen[key] = true
					hotMsgByEndpoint[ev.EndpointID] = append(hotMsgByEndpoint[ev.EndpointID], ev.Message)
				}
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
		n.Risk, n.RiskReasons = s.nodeRisk(ctx, ep, snap, hotByEndpoint[ep.ID])
		// For a critical node, surface the actual triggering events as the
		// reason so the inspect panel explains the "why".
		if n.Risk == "critical" && len(hotMsgByEndpoint[ep.ID]) > 0 {
			n.RiskReasons = hotMsgByEndpoint[ep.ID]
		}
		nodes = append(nodes, n)
	}

	if len(ext) > 0 {
		// Explode external talk into one node per destination domain (the real
		// website/service), with a single "internet" node for traffic we
		// couldn't attribute to a domain. Each endpoint gets one edge per
		// destination node.
		extNodes := map[string]*model.TopoNode{} // node id -> node
		type edgeAgg struct {
			count     int
			bytes     uint64
			remotes   []string
			malicious bool
		}
		edgeAggs := map[string]*edgeAgg{} // "src|dst" -> agg

		for id, a := range ext {
			for ip, rs := range a.remotes {
				mal := s.ti != nil && (s.ti.isBad(ip) || s.ti.isBadDomain(rs.domain))
				var nodeID, host, group string
				if rs.domain != "" {
					nodeID, host = "ext:"+rs.domain, rs.domain
					if s.geo != nil {
						group = s.geo.label(ip)
					}
				} else {
					nodeID, host = "internet", "internet"
				}
				n := extNodes[nodeID]
				if n == nil {
					n = &model.TopoNode{ID: nodeID, Hostname: host, Online: true, External: true, Group: group}
					extNodes[nodeID] = n
				}
				if mal {
					n.Risk, n.RiskReasons = "critical", []string{"known-malicious destination"}
				}
				key := id + "|" + nodeID
				ea := edgeAggs[key]
				if ea == nil {
					ea = &edgeAgg{}
					edgeAggs[key] = ea
				}
				ea.count += rs.count
				ea.bytes += rs.bytes
				if len(ea.remotes) < 5 {
					ea.remotes = append(ea.remotes, ip)
				}
				if mal {
					ea.malicious = true
				}
			}
		}
		for _, n := range extNodes {
			nodes = append(nodes, *n)
		}
		for key, ea := range edgeAggs {
			src, dst, _ := strings.Cut(key, "|")
			var names []string
			if dst == "internet" { // label the raw IPs with reverse-DNS
				for _, ip := range ea.remotes {
					names = append(names, s.rdns.name(ip))
				}
			}
			edges = append(edges, model.TopoEdge{
				Src: src, Dst: dst, Count: ea.count, Bytes: ea.bytes,
				Remotes: ea.remotes, RemoteNames: names, Malicious: ea.malicious,
			})
		}
	}

	if declared {
		addDeclaredOverlay(nodes, &edges, snaps, inScope, s.ips, eps)
	}

	if edges == nil {
		edges = []model.TopoEdge{}
	}
	return nodes, edges, nil
}

// addDeclaredOverlay augments the graph with configured dependencies from each
// host's snapshot: cross-host deps (replication, HA monitor) become dashed
// "declared" edges resolved to the target fleet host; host-local systemd deps are
// attached to the node for the inspector. Observed and declared edges coexist, so
// you can see which configured deps are actually exercised (both) and which are
// declared-but-idle (declared only).
func addDeclaredOverlay(nodes []model.TopoNode, edges *[]model.TopoEdge, snaps map[string]*model.Snapshot, inScope map[string]bool, ips *ipIndex, eps []model.EndpointSummary) {
	hostToID := map[string]string{}
	for _, ep := range eps {
		if ep.Hostname != "" {
			hostToID[ep.Hostname] = ep.ID
		}
	}
	// Host-local (systemd) deps → node inspector.
	for i := range nodes {
		snap := snaps[nodes[i].ID]
		if snap == nil {
			continue
		}
		for _, dd := range snap.DeclaredDeps {
			if dd.TargetHost == "" {
				nodes[i].DeclaredDeps = append(nodes[i].DeclaredDeps, dd)
			}
		}
	}
	// Cross-host deps → declared edges.
	seen := map[string]bool{}
	for id, snap := range snaps {
		if snap == nil || !inScope[id] {
			continue
		}
		for _, dd := range snap.DeclaredDeps {
			if dd.TargetHost == "" {
				continue
			}
			dst := ips.lookup(dd.TargetHost)
			if dst == "" {
				dst = hostToID[dd.TargetHost]
			}
			if dst == "" || dst == id || !inScope[dst] {
				continue // target isn't a monitored fleet host
			}
			k := id + "|" + dst + "|" + dd.Kind
			if seen[k] {
				continue
			}
			seen[k] = true
			*edges = append(*edges, model.TopoEdge{
				Src: id, Dst: dst, Internal: true, Declared: true,
				DepKind: dd.Kind, Hard: dd.Hard, Count: 1,
			})
		}
	}
}
