package server

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"

	"github.com/soc-foundry/varro/internal/model"
)

// handleVulnPriority ranks vulnerable endpoints by runtime reachability: raw
// CVSS weight scaled by whether the host is internet-facing, talking to
// known-malicious destinations, and currently active. It answers "what do I
// patch first" far better than severity counts alone.
func (s *Server) handleVulnPriority(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	out, err := s.buildVulnPriority(r.Context(), scope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"endpoints": out})
}

func (s *Server) buildVulnPriority(ctx context.Context, scope []string) ([]model.VulnPriority, error) {
	eps, err := s.store.Endpoints(ctx, scope)
	if err != nil {
		return nil, err
	}
	online := map[string]bool{}
	host := map[string]string{}
	for _, ep := range eps {
		online[ep.ID] = ep.Online
		host[ep.ID] = ep.Hostname
	}

	vulnBy, err := s.store.VulnSeverityByEndpoint(ctx, scope)
	if err != nil {
		return nil, err
	}
	if len(vulnBy) == 0 {
		return []model.VulnPriority{}, nil
	}

	// Exposure signals from the live topology (last 24h).
	_, edges, err := s.buildTopology(ctx, scope, 1440)
	if err != nil {
		return nil, err
	}
	internetFacing := map[string]bool{}
	talksMalicious := map[string]bool{}
	for _, e := range edges {
		if e.Internal {
			continue
		}
		internetFacing[e.Src] = true
		if e.Malicious {
			talksMalicious[e.Src] = true
		}
	}

	out := make([]model.VulnPriority, 0, len(vulnBy))
	for epID, raw := range vulnBy {
		var p model.VulnPriority
		p.EndpointID = epID
		p.Hostname = host[epID]
		if p.Hostname == "" {
			p.Hostname = epID
		}
		for rawSev, n := range raw {
			switch normalizeSeverity(rawSev) {
			case "critical":
				p.Critical += n
			case "high":
				p.High += n
			case "medium":
				p.Medium += n
			case "low":
				p.Low += n
			}
			p.Total += n
		}
		p.Online = online[epID]
		p.InternetFacing = internetFacing[epID]
		p.Malicious = talksMalicious[epID]

		// Severity weight, then scale by runtime reachability.
		weight := float64(p.Critical*10 + p.High*5 + p.Medium*2 + p.Low*1)
		mult := 1.0
		if p.InternetFacing {
			mult += 2
		}
		if p.Malicious {
			mult += 3
		}
		if p.Online {
			mult += 0.5
		}
		p.Score = int(math.Round(weight * mult))

		sev := fmt.Sprintf("%d critical · %d high · %d medium", p.Critical, p.High, p.Medium)
		p.Reasons = append(p.Reasons, sev)
		if p.Malicious {
			p.Reasons = append(p.Reasons, "talks to a known-malicious destination")
		}
		if p.InternetFacing {
			p.Reasons = append(p.Reasons, "internet-facing (active external traffic)")
		}
		if !p.Online {
			p.Reasons = append(p.Reasons, "offline — deprioritized")
		}
		out = append(out, p)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Total > out[j].Total
	})
	return out, nil
}
