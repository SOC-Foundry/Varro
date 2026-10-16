package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

const rolloutCacheTTL = 30 * time.Second

// cachedRollout returns the staged-rollout config, cached briefly so a per-agent
// config poll doesn't hit the DB every time (and so both collectors answer
// consistently within the TTL — the anti-flap property).
func (s *Server) cachedRollout(ctx context.Context) model.AgentRollout {
	s.rolloutMu.Lock()
	defer s.rolloutMu.Unlock()
	if time.Since(s.rolloutAt) < rolloutCacheTTL {
		return s.rolloutCache
	}
	r, err := s.store.GetRollout(ctx)
	if err != nil {
		s.log.Error("rollout: load", "error", err)
		return s.rolloutCache // keep the last good value on error
	}
	s.rolloutCache, s.rolloutAt = r, time.Now()
	return r
}

// desiredVersionFor resolves the target agent version for one agent: the staged
// rollout (canary agents get the canary version, everyone else the stable one)
// when configured, otherwise the server's configured desired version. Because the
// rollout lives in the shared DB, both collectors resolve the same target for a
// given agent — so a staged rollout doesn't flap agents across the LB.
func (s *Server) desiredVersionFor(ctx context.Context, agentID string) string {
	r := s.cachedRollout(ctx)
	if r.StableVersion == "" {
		return s.cfg.AgentDesiredVersion // backward-compatible: env/flag pin
	}
	if r.CanaryVersion != "" && agentID != "" {
		for _, id := range r.CanaryIDs {
			if id == agentID {
				return r.CanaryVersion
			}
		}
	}
	return r.StableVersion
}

// handleFleet serves the fleet-health summary (instance admin): version spread,
// online/offline, how many are behind their target version, and per-agent rows.
func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	eps, err := s.store.Endpoints(r.Context(), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rollout := s.cachedRollout(r.Context())
	canary := map[string]bool{}
	for _, id := range rollout.CanaryIDs {
		canary[id] = true
	}
	sum := model.FleetSummary{Versions: map[string]int{}, Rollout: rollout, Agents: []model.FleetAgent{}}
	for _, ep := range eps {
		sum.Total++
		ver := ep.AgentVersion
		if ver == "" {
			ver = "unknown"
		}
		sum.Versions[ver]++
		target := s.desiredVersionFor(r.Context(), ep.ID)
		upToDate := target == "" || target == "dev" || ep.AgentVersion == target
		if !upToDate {
			sum.BehindTarget++
		}
		if ep.Online {
			sum.Online++
		}
		sensor := ""
		if snap, err := s.store.Latest(r.Context(), ep.ID); err == nil && snap != nil && snap.EBPF {
			sensor = execSensorLabel(ep.Platform)
		}
		sum.Agents = append(sum.Agents, model.FleetAgent{
			ID: ep.ID, Hostname: ep.Hostname, Platform: ep.Platform,
			AgentVersion: ep.AgentVersion, Target: target, Canary: canary[ep.ID],
			UpToDate: upToDate, Online: ep.Online, Sensor: sensor, LastSeen: ep.LastSeen,
		})
	}
	writeJSON(w, sum)
}

// execSensorLabel names the short-lived exec sensor an active agent uses, by OS.
func execSensorLabel(platform string) string {
	p := strings.ToLower(platform)
	switch {
	case strings.Contains(p, "windows"):
		return "ETW"
	case strings.Contains(p, "linux") || strings.Contains(p, "debian") || strings.Contains(p, "ubuntu") ||
		strings.Contains(p, "arch") || strings.Contains(p, "rhel") || strings.Contains(p, "centos"):
		return "eBPF"
	default:
		return "polling"
	}
}

// handleRolloutGet returns the current staged-rollout config (instance admin).
func (s *Server) handleRolloutGet(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, s.cachedRollout(r.Context()))
}

// handleRolloutSet updates the staged-rollout config (instance admin). Setting an
// empty stable_version clears the rollout (falls back to the env/flag pin).
func (s *Server) handleRolloutSet(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req model.AgentRollout
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.StableVersion = strings.TrimSpace(req.StableVersion)
	req.CanaryVersion = strings.TrimSpace(req.CanaryVersion)
	if req.CanaryIDs == nil {
		req.CanaryIDs = []string{}
	}
	if err := s.store.SetRollout(r.Context(), req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.rolloutMu.Lock()
	s.rolloutAt = time.Time{} // invalidate cache so the change takes effect immediately
	s.rolloutMu.Unlock()
	s.audit(r, "agent.rollout.set", "", req.StableVersion+" / canary "+req.CanaryVersion)
	s.log.Info("agent rollout updated", "stable", req.StableVersion, "canary", req.CanaryVersion, "canary_count", len(req.CanaryIDs))
	writeJSON(w, map[string]bool{"ok": true})
}
