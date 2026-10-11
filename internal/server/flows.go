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
	nodes, edges, err := s.buildTopology(r.Context(), scope, minutes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := make(map[string]string, len(nodes))
	for _, n := range nodes {
		name[n.ID] = n.Hostname
	}

	type agg struct {
		bytes uint64
		count int
		geo   string
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
		if a.geo == "" {
			for _, g := range e.RemoteGeo {
				if g != "" {
					a.geo = g
					break
				}
			}
		}
	}

	out := make([]model.FlowTalker, 0, len(byDest))
	for dst, a := range byDest {
		dn := name[dst]
		if dn == "" {
			dn = dst
		}
		out = append(out, model.FlowTalker{
			Dest:      dn,
			Bytes:     a.bytes,
			Count:     a.count,
			Sources:   len(a.srcs),
			Geo:       a.geo,
			Country:   countryOf(a.geo),
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
