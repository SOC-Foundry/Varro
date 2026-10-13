package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/soc-foundry/varro/internal/model"
)

// incidentInScope resolves the incident id, verifies the caller may read its org,
// and returns (id, org). Triage actions are allowed to anyone with read scope on
// the org (analysts), not just org-admins.
func (s *Server) incidentInScope(w http.ResponseWriter, r *http.Request) (int64, string, bool) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return 0, "", false
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad incident id", http.StatusBadRequest)
		return 0, "", false
	}
	org, err := s.store.IncidentOrg(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return 0, "", false
	}
	if org == "" {
		http.Error(w, "unknown incident", http.StatusNotFound)
		return 0, "", false
	}
	if scope != nil {
		allowed := false
		for _, o := range scope {
			if o == org {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "unknown incident", http.StatusNotFound) // don't reveal to other tenants
			return 0, "", false
		}
	}
	return id, org, true
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	incs, err := s.store.Incidents(r.Context(), scope, r.URL.Query().Get("status"), limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if incs == nil {
		incs = []model.Incident{}
	}
	writeJSON(w, map[string]any{"incidents": incs})
}

func (s *Server) handleIncidentDetail(w http.ResponseWriter, r *http.Request) {
	id, _, ok := s.incidentInScope(w, r)
	if !ok {
		return
	}
	inc, err := s.store.IncidentDetail(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if inc == nil {
		http.Error(w, "unknown incident", http.StatusNotFound)
		return
	}
	writeJSON(w, inc)
}

func (s *Server) handleIncidentAck(w http.ResponseWriter, r *http.Request) {
	s.incidentStatus(w, r, model.IncidentAck)
}

func (s *Server) handleIncidentResolve(w http.ResponseWriter, r *http.Request) {
	s.incidentStatus(w, r, model.IncidentResolved)
}

func (s *Server) incidentStatus(w http.ResponseWriter, r *http.Request, status string) {
	id, org, ok := s.incidentInScope(w, r)
	if !ok {
		return
	}
	if err := s.store.SetIncidentStatus(r.Context(), id, status, s.actor(r)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "incident."+status, org, "incident "+strconv.FormatInt(id, 10))
	writeJSON(w, map[string]string{"status": status})
}

func (s *Server) handleIncidentAssign(w http.ResponseWriter, r *http.Request) {
	id, org, ok := s.incidentInScope(w, r)
	if !ok {
		return
	}
	var req struct {
		Assignee string `json:"assignee"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.store.AssignIncident(r.Context(), id, req.Assignee, s.actor(r)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "incident.assign", org, "incident "+strconv.FormatInt(id, 10)+" → "+req.Assignee)
	writeJSON(w, map[string]string{"assignee": req.Assignee})
}

func (s *Server) handleIncidentNote(w http.ResponseWriter, r *http.Request) {
	id, _, ok := s.incidentInScope(w, r)
	if !ok {
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil || req.Note == "" {
		http.Error(w, "need {\"note\": \"...\"}", http.StatusBadRequest)
		return
	}
	if err := s.store.AddIncidentNote(r.Context(), id, s.actor(r), req.Note); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"added": true})
}

// incidentSevFromAlert maps an alert's routing severity to the incident scale.
func incidentSevFromAlert(rule string) string {
	switch alertSeverity("firing", rule) {
	case model.SevCritical:
		return "CRITICAL"
	case model.SevWarning:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
