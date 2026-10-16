package server

import (
	"context"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// undeclaredTarget reports whether dst is an undeclared dependency target: the
// source has at least one resolvable cross-host declared dep, yet dst is not among
// them. Returns false when no declared deps resolve to fleet hosts (can't judge).
func undeclaredTarget(deps []model.DeclaredDep, ips *ipIndex, dst string) bool {
	resolvable, matched := 0, false
	for _, dd := range deps {
		if dd.TargetHost == "" {
			continue
		}
		if t := ips.lookup(dd.TargetHost); t != "" {
			resolvable++
			if t == dst {
				matched = true
			}
		}
	}
	return resolvable > 0 && !matched
}

// dependencyHealthLoop checks, on the leader, whether any hard declared
// dependency's target host is offline — an availability risk — and alerts
// (rate-limited). Runs every 5 minutes.
func (s *Server) dependencyHealthLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.isLeader() {
				s.checkDependencyHealth(ctx)
			}
		}
	}
}

// checkDependencyHealth scans every endpoint's hard, cross-host declared deps and
// raises a dep_target_down event when the dependency's target endpoint is offline.
func (s *Server) checkDependencyHealth(ctx context.Context) {
	eps, err := s.store.Endpoints(ctx, nil)
	if err != nil {
		s.log.Error("dep health: list endpoints", "error", err)
		return
	}
	online := map[string]bool{}
	name := map[string]string{}
	org := map[string]string{}
	for _, ep := range eps {
		online[ep.ID] = ep.Online
		name[ep.ID] = ep.Hostname
		org[ep.ID] = ep.OrgID
	}
	for _, ep := range eps {
		snap, err := s.store.Latest(ctx, ep.ID)
		if err != nil || snap == nil {
			continue
		}
		for _, dd := range snap.DeclaredDeps {
			if !dd.Hard || dd.TargetHost == "" {
				continue
			}
			dst := s.ips.lookup(dd.TargetHost)
			if dst == "" {
				continue
			}
			up, known := online[dst]
			if !known || up {
				continue // target isn't a monitored fleet host, or it's online
			}
			if !s.driftShouldAlert("depdown|"+ep.ID+"|"+dst, time.Hour) {
				continue
			}
			msg := "dependency down: " + ep.Hostname + " depends on " + name[dst] +
				" (" + dd.Kind + ") but it is offline"
			if err := s.store.InsertServerEvent(ctx, org[ep.ID], ep.ID, model.EventDepTargetDown, msg); err != nil {
				continue
			}
			s.log.Warn("declared dependency target down", "src", ep.Hostname, "dst", name[dst], "kind", dd.Kind)
			s.notifyEvents(org[ep.ID], ep.Hostname, []model.Event{{Type: model.EventDepTargetDown, Message: msg}})
			s.siemForward(org[ep.ID], ep.Hostname, model.EventDepTargetDown, "HIGH", "", msg)
		}
	}
}
