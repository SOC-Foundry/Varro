package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// alertScope resolves the path {id} to an alert, authorizing the caller as an
// admin of the alert's org (operator action, same bar as response actions).
// ok=false means a response was already written.
func (s *Server) alertScope(w http.ResponseWriter, r *http.Request) (id int64, org string, ok bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad alert id", http.StatusBadRequest)
		return 0, "", false
	}
	org, _, err = s.store.AlertOrg(r.Context(), id)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return 0, "", false
	}
	if org == "" {
		// Don't reveal existence to non-admins of other orgs.
		if !s.adminAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return 0, "", false
		}
		http.Error(w, "unknown alert", http.StatusNotFound)
		return 0, "", false
	}
	if !s.orgAdminAuthorized(r, org) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return 0, "", false
	}
	return id, org, true
}

// handleAlertAck acknowledges a firing alert ("someone's on it").
func (s *Server) handleAlertAck(w http.ResponseWriter, r *http.Request) {
	id, org, ok := s.alertScope(w, r)
	if !ok {
		return
	}
	who := s.actor(r)
	updated, err := s.store.AckAlert(r.Context(), id, who)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !updated {
		http.Error(w, "alert is not firing", http.StatusConflict)
		return
	}
	s.audit(r, "alert.ack", org, "acknowledged alert "+strconv.FormatInt(id, 10))
	writeJSON(w, map[string]string{"status": "acknowledged", "by": who})
}

// handleAlertAssign sets (or clears, with empty) an alert's assignee.
func (s *Server) handleAlertAssign(w http.ResponseWriter, r *http.Request) {
	id, org, ok := s.alertScope(w, r)
	if !ok {
		return
	}
	var req struct {
		Assignee string `json:"assignee"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
	assignee := strings.TrimSpace(req.Assignee)
	if len(assignee) > 254 {
		http.Error(w, "assignee too long", http.StatusBadRequest)
		return
	}
	updated, err := s.store.AssignAlert(r.Context(), id, assignee)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !updated {
		http.Error(w, "unknown alert", http.StatusNotFound)
		return
	}
	detail := "assigned alert " + strconv.FormatInt(id, 10) + " to " + assignee
	if assignee == "" {
		detail = "unassigned alert " + strconv.FormatInt(id, 10)
	}
	s.audit(r, "alert.assign", org, detail)
	writeJSON(w, map[string]string{"status": "assigned", "assignee": assignee})
}

// handleAlertResolve manually resolves a firing alert with an operator note.
func (s *Server) handleAlertResolve(w http.ResponseWriter, r *http.Request) {
	id, org, ok := s.alertScope(w, r)
	if !ok {
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req)
	note := strings.TrimSpace(req.Note)
	if len(note) > 2000 {
		note = note[:2000]
	}
	// Attribute the resolution to the operator.
	stamped := note
	if who := s.actor(r); who != "" {
		if stamped != "" {
			stamped = who + ": " + stamped
		} else {
			stamped = "resolved by " + who
		}
	}
	updated, err := s.store.ResolveAlertManual(r.Context(), id, stamped)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !updated {
		http.Error(w, "alert is not firing", http.StatusConflict)
		return
	}
	s.audit(r, "alert.resolve", org, "resolved alert "+strconv.FormatInt(id, 10))
	writeJSON(w, map[string]string{"status": "resolved", "note": stamped})
}
