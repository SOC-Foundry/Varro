package server

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/soc-foundry/varro/internal/model"
)

// handleFlows returns the fleet's top external talkers: each distinct external
// destination (domain or "internet") with total conntrack bytes, connection
// count, how many fleet hosts reached it, and geo/threat annotation. It reuses
// the topology aggregation so the numbers line up with the map view.
func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	minutes := 60
	if m := r.URL.Query().Get("minutes"); m != "" {
		if v, err := strconv.Atoi(m); err == nil && v > 0 && v <= 10080 {
			minutes = v
		}
	}
	nodes, edges, err := s.buildTopology(r.Context(), scope, minutes, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// External destinations carry their geo label on the node's Group field
	// ("US · AS15169 Google"), set by buildTopology when GeoIP is enabled.
	name := make(map[string]string, len(nodes))
	geoByNode := make(map[string]string, len(nodes))
	for _, n := range nodes {
		name[n.ID] = n.Hostname
		geoByNode[n.ID] = n.Group
	}

	type agg struct {
		bytes uint64
		count int
		mal   bool
		srcs  map[string]bool
	}
	byDest := map[string]*agg{}
	for _, e := range edges {
		if e.Internal {
			continue
		}
		a := byDest[e.Dst]
		if a == nil {
			a = &agg{srcs: map[string]bool{}}
			byDest[e.Dst] = a
		}
		a.bytes += e.Bytes
		a.count += e.Count
		a.srcs[e.Src] = true
		a.mal = a.mal || e.Malicious
	}

	out := make([]model.FlowTalker, 0, len(byDest))
	for dst, a := range byDest {
		dn := name[dst]
		if dn == "" {
			dn = dst
		}
		geo := geoByNode[dst]
		out = append(out, model.FlowTalker{
			Dest:      dn,
			Bytes:     a.bytes,
			Count:     a.count,
			Sources:   len(a.srcs),
			Geo:       geo,
			Country:   countryOf(geo),
			CDN:       isCDN(dn, geo),
			Malicious: a.mal,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Count > out[j].Count
	})
	writeJSON(w, map[string]any{"minutes": minutes, "talkers": out})
}

// cdnASNs are well-known CDN / anycast provider AS numbers whose IP geolocation
// is meaningless (an edge PoP, not where the service "is"). Hyperscaler compute
// ASNs (Google/Amazon/Microsoft general) are intentionally excluded — their geo,
// while imperfect, is at least consistent; CDN hostnames catch their CDN arms.
var cdnASNs = map[string]bool{
	"AS13335": true,                                                                                      // Cloudflare
	"AS54113": true,                                                                                      // Fastly
	"AS20940": true, "AS16625": true, "AS16702": true, "AS20189": true, "AS35994": true, "AS23454": true, // Akamai
	"AS15133": true,                  // Edgecast / Verizon Media
	"AS22822": true, "AS38622": true, // Limelight / Edgio
	"AS33438": true, "AS20446": true, // StackPath / Highwinds
	"AS19551": true, // Imperva / Incapsula
}

// isCDN reports whether a destination is a CDN/anycast endpoint whose country
// geolocation shouldn't be trusted: a "cdn" in the hostname, a known CDN name in
// the geo label, or a known CDN AS number.
func isCDN(dest, geo string) bool {
	if strings.Contains(strings.ToLower(dest), "cdn") {
		return true
	}
	g := strings.ToLower(geo)
	for _, kw := range []string{"cloudflare", "akamai", "fastly", "cloudfront", "edgecast", "edgio", "limelight", "stackpath", "incapsula", "imperva"} {
		if strings.Contains(g, kw) {
			return true
		}
	}
	if i := strings.Index(geo, "AS"); i >= 0 {
		as := geo[i:]
		if sp := strings.IndexAny(as, " ·"); sp > 0 {
			as = as[:sp]
		}
		if cdnASNs[as] {
			return true
		}
	}
	return false
}

// countryOf pulls the leading ISO-3166 alpha-2 code out of a geo label like
// "US · AS15169 Google" (what geoCache produces). Returns "" if absent.
func countryOf(geo string) string {
	geo = strings.TrimSpace(geo)
	if len(geo) >= 2 {
		c0, c1 := geo[0], geo[1]
		if c0 >= 'A' && c0 <= 'Z' && c1 >= 'A' && c1 <= 'Z' {
			// Ensure it's a standalone token, not the start of a longer word.
			if len(geo) == 2 || geo[2] == ' ' || geo[2] == '/' {
				return geo[:2]
			}
		}
	}
	return ""
}
