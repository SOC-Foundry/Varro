package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/soc-foundry/varro/internal/model"
)

// handleAgentActions delivers an agent its pending response actions (claimed,
// so they aren't re-sent mid-flight). Agent-token auth.
func (s *Server) handleAgentActions(w http.ResponseWriter, r *http.Request) {
	agentID, _, ok := s.agentAuthorized(r)
	if !ok || agentID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	actions, err := s.store.ClaimActions(r.Context(), agentID)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if actions == nil {
		actions = []model.Action{}
	}
	writeJSON(w, actions)
}

// handleActionAck records an action's result. The acking agent must own the
// action's target endpoint.
func (s *Server) handleActionAck(w http.ResponseWriter, r *http.Request) {
	agentID, _, ok := s.agentAuthorized(r)
	if !ok || agentID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad action id", http.StatusBadRequest)
		return
	}
	owner, err := s.store.ActionEndpoint(r.Context(), id)
	if err != nil || owner == "" {
		http.Error(w, "unknown action", http.StatusNotFound)
		return
	}
	if owner != agentID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		OK     bool   `json:"ok"`
		Result string `json:"result"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.store.AckAction(r.Context(), id, req.OK, req.Result); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	// Audit the outcome in the endpoint's event feed.
	if org, _ := s.store.EndpointOrg(r.Context(), agentID); org != "" {
		verb := "succeeded"
		if !req.OK {
			verb = "FAILED"
		}
		s.store.InsertServerEvent(r.Context(), org, agentID, "action_result",
			fmt.Sprintf("response action %s: %s", verb, req.Result))
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// handleIssueAction queues a response action against an endpoint. Org admins
// (and up) for the endpoint's org only; every issue is audited.
func (s *Server) handleIssueAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	org, err := s.store.EndpointOrg(r.Context(), id)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if org == "" {
		// Don't reveal endpoint existence to non-admins of other orgs.
		if !s.adminAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		http.Error(w, "unknown endpoint", http.StatusNotFound)
		return
	}
	if !s.orgAdminAuthorized(r, org) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Type string `json:"type"`
		Arg  string `json:"arg"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !model.ValidActionType(req.Type) {
		http.Error(w, "unsupported action type", http.StatusBadRequest)
		return
	}
	if req.Type == model.ActionKillProcess {
		if n, err := strconv.Atoi(req.Arg); err != nil || n <= 1 {
			http.Error(w, "kill_process requires a valid pid", http.StatusBadRequest)
			return
		}
	}

	issuer := "master-token"
	if u, ok := s.sessionUser(r); ok {
		issuer = u.Email
	}
	actionID, err := s.store.EnqueueAction(r.Context(), id, req.Type, req.Arg, issuer)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	// Audit the issuance immediately (distinct from the later result event).
	detail := req.Type
	if req.Arg != "" {
		detail += " " + req.Arg
	}
	s.store.InsertServerEvent(r.Context(), org, id, "action_issued",
		fmt.Sprintf("%s issued response action: %s", issuer, detail))
	s.log.Info("response action issued", "endpoint", id, "type", req.Type, "arg", req.Arg, "by", issuer)
	writeJSON(w, map[string]any{"id": actionID, "status": model.ActionPending})
}

// handleListActions returns an endpoint's recent actions (read scope).
func (s *Server) handleListActions(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	id, ok := s.endpointInScope(w, r, scope)
	if !ok {
		return
	}
	actions, err := s.store.Actions(r.Context(), id, 50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if actions == nil {
		actions = []model.Action{}
	}
	writeJSON(w, actions)
}
