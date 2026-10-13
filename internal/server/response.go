package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

var detSevRank = map[string]int{"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

// runPlaybooks executes matching auto-response playbooks for a fired detection.
// Called from fireDetection (already rate-limited by detector.should).
func (s *Server) runPlaybooks(ctx context.Context, orgID string, snap *model.Snapshot, rule, severity string) {
	od := s.orgDetections(ctx, orgID)
	for _, pb := range od.playbooks {
		if !pb.Enabled {
			continue
		}
		if pb.OnRule != "" && !strings.Contains(strings.ToLower(rule), strings.ToLower(pb.OnRule)) {
			continue
		}
		if pb.OnSeverity != "" && detSevRank[severity] < detSevRank[pb.OnSeverity] {
			continue
		}
		switch pb.Action {
		case model.ActionIsolate:
			s.autoIsolate(ctx, orgID, snap, pb, rule)
		}
	}
}

// autoIsolate network-contains an endpoint in response to a detection, unless it
// is already isolated.
func (s *Server) autoIsolate(ctx context.Context, orgID string, snap *model.Snapshot, pb model.Playbook, rule string) {
	if last, _ := s.store.LatestContainment(ctx, snap.AgentID); last == model.ActionIsolate {
		return // already contained
	}
	if _, err := s.store.EnqueueAction(ctx, snap.AgentID, model.ActionIsolate, "", "auto:"+pb.Name); err != nil {
		s.log.Error("auto-isolate enqueue", "endpoint", snap.Hostname, "error", err)
		return
	}
	msg := fmt.Sprintf("auto-response: isolated %s — playbook %q matched detection %s", snap.Hostname, pb.Name, rule)
	s.store.InsertServerEvent(ctx, orgID, snap.AgentID, model.EventDetection, "[HIGH] auto_response: "+msg)
	s.log.Warn("auto-response", "action", "isolate", "endpoint", snap.Hostname, "playbook", pb.Name, "rule", rule)
	s.notifyEvents(orgID, snap.Hostname, []model.Event{{Type: model.EventDetection, Message: "[HIGH] auto_response: " + msg}})
	s.siemForward(orgID, snap.Hostname, "auto_response", "HIGH", "", msg)
}

// alertSilenced reports whether an alert transition should skip paging because a
// maintenance-window silence matches it.
func (s *Server) alertSilenced(ctx context.Context, orgID, rule, endpointID string) bool {
	if orgID == "" {
		return false
	}
	sils, err := s.store.ActiveSilences(ctx, orgID)
	if err != nil {
		return false
	}
	for _, sl := range sils {
		if sl.MatchRule != "" && !strings.Contains(strings.ToLower(rule), strings.ToLower(sl.MatchRule)) {
			continue
		}
		if sl.MatchEndpoint != "" && sl.MatchEndpoint != endpointID {
			continue
		}
		return true
	}
	return false
}

// ---- playbook handlers ----

func (s *Server) handlePlaybooksList(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	pbs, err := s.store.Playbooks(r.Context(), orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if pbs == nil {
		pbs = []model.Playbook{}
	}
	writeJSON(w, map[string]any{"playbooks": pbs})
}

func (s *Server) handlePlaybookCreate(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	var pb model.Playbook
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&pb); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pb.Name = strings.TrimSpace(pb.Name)
	if pb.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if pb.Action == "" {
		pb.Action = model.ActionIsolate
	}
	if pb.Action != model.ActionIsolate {
		http.Error(w, "action must be isolate", http.StatusBadRequest)
		return
	}
	if pb.OnSeverity != "" && !validSeverity(pb.OnSeverity) {
		http.Error(w, "on_severity must be CRITICAL, HIGH, MEDIUM, or LOW", http.StatusBadRequest)
		return
	}
	pb.OrgID = orgID
	pb.Enabled = true
	created, err := s.store.CreatePlaybook(r.Context(), pb)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.invalidateDetections(orgID)
	s.audit(r, "playbook.create", orgID, created.Name)
	writeJSON(w, created)
}

func (s *Server) handlePlaybookUpdate(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	changed, err := s.store.SetPlaybookEnabled(r.Context(), orgID, r.PathValue("pbID"), req.Enabled)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !changed {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.invalidateDetections(orgID)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handlePlaybookDelete(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	removed, err := s.store.DeletePlaybook(r.Context(), orgID, r.PathValue("pbID"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.invalidateDetections(orgID)
	s.audit(r, "playbook.delete", orgID, r.PathValue("pbID"))
	writeJSON(w, map[string]bool{"removed": true})
}

// ---- silence handlers ----

func (s *Server) handleSilencesList(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	sils, err := s.store.Silences(r.Context(), orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if sils == nil {
		sils = []model.Silence{}
	}
	writeJSON(w, map[string]any{"silences": sils})
}

func (s *Server) handleSilenceCreate(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	var req struct {
		Name          string `json:"name"`
		MatchRule     string `json:"match_rule"`
		MatchEndpoint string `json:"match_endpoint"`
		Hours         int    `json:"hours"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if req.Hours <= 0 {
		req.Hours = 1
	}
	if req.Hours > 720 {
		req.Hours = 720
	}
	created, err := s.store.CreateSilence(r.Context(), model.Silence{
		OrgID: orgID, Name: req.Name, MatchRule: req.MatchRule, MatchEndpoint: req.MatchEndpoint,
		Until: time.Now().Add(time.Duration(req.Hours) * time.Hour).UTC(),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "silence.create", orgID, created.Name)
	writeJSON(w, created)
}

func (s *Server) handleSilenceDelete(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	removed, err := s.store.DeleteSilence(r.Context(), orgID, r.PathValue("silID"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.audit(r, "silence.delete", orgID, r.PathValue("silID"))
	writeJSON(w, map[string]bool{"removed": true})
}
