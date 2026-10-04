package server

import (
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
	nodes := make([]model.TopoNode, 0, len(eps)+1)
	inScope := map[string]bool{}
	fleetIPs := map[string]bool{}
	for _, ep := range eps {
		nodes = append(nodes, model.TopoNode{ID: ep.ID, Hostname: ep.Hostname, Online: ep.Online})
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
			var remotes []string
			for i := 0; i < len(rcs) && i < 5; i++ {
				remotes = append(remotes, rcs[i].ip)
			}
			edges = append(edges, model.TopoEdge{
				Src: id, Dst: "internet", Count: a.count, Remotes: remotes,
			})
		}
	}

	if edges == nil {
		edges = []model.TopoEdge{}
	}
	writeJSON(w, map[string]any{"nodes": nodes, "edges": edges, "window_minutes": minutes})
}
