package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

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
	if err := validateActionArg(req.Type, req.Arg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	issuer := "master-token"
	if u, ok := s.sessionUser(r); ok {
		issuer = u.Email
	}
	// Manually-issued actions are proposed and need a separate approval before the
	// agent can run them (two-person-friendly; auto-response bypasses this).
	actionID, err := s.store.EnqueueAction(r.Context(), id, req.Type, req.Arg, issuer, model.ActionProposed)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	detail := req.Type
	if req.Arg != "" {
		detail += " " + req.Arg
	}
	s.store.InsertServerEvent(r.Context(), org, id, "action_proposed",
		fmt.Sprintf("%s proposed response action: %s (awaiting approval)", issuer, detail))
	s.log.Info("response action proposed", "endpoint", id, "type", req.Type, "arg", req.Arg, "by", issuer)
	s.audit(r, "action.propose."+req.Type, org, detail+" on "+id)
	writeJSON(w, map[string]any{"id": actionID, "status": model.ActionProposed})
}

// validateActionArg checks the argument for action types that require one.
func validateActionArg(typ, arg string) error {
	switch typ {
	case model.ActionKillProcess:
		if n, err := strconv.Atoi(arg); err != nil || n <= 1 {
			return fmt.Errorf("kill_process requires a valid pid")
		}
	case model.ActionBlockIP, model.ActionUnblockIP:
		if net.ParseIP(strings.TrimSpace(arg)) == nil {
			return fmt.Errorf("%s requires a valid IP address", typ)
		}
	case model.ActionQuarantineFile:
		if strings.TrimSpace(arg) == "" {
			return fmt.Errorf("quarantine_file requires a file path")
		}
	}
	return nil
}

// handleActionDecision approves (→ pending, agent runs it) or rejects a proposed
// action. Org admin for the action's endpoint; audited. Self-approval is allowed
// (so solo operators aren't deadlocked) but recorded as such.
func (s *Server) handleActionDecision(w http.ResponseWriter, r *http.Request, approve bool) {
	actID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad action id", http.StatusBadRequest)
		return
	}
	act, err := s.store.ActionByID(r.Context(), actID)
	if err != nil || act.ID == 0 {
		http.Error(w, "unknown action", http.StatusNotFound)
		return
	}
	org, _ := s.store.EndpointOrg(r.Context(), act.EndpointID)
	if org == "" || !s.orgAdminAuthorized(r, org) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	approver := "master-token"
	if u, ok := s.sessionUser(r); ok {
		approver = u.Email
	}
	detail := act.Type
	if act.Arg != "" {
		detail += " " + act.Arg
	}
	if approve {
		ok, err := s.store.ApproveAction(r.Context(), actID, approver)
		if err != nil {
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "action is not awaiting approval", http.StatusConflict)
			return
		}
		note := ""
		if approver == act.IssuedBy && approver != "master-token" {
			note = " (self-approved)"
		}
		s.store.InsertServerEvent(r.Context(), org, act.EndpointID, "action_approved",
			fmt.Sprintf("%s approved response action: %s%s", approver, detail, note))
		s.audit(r, "action.approve."+act.Type, org, detail+" on "+act.EndpointID)
		s.log.Info("response action approved", "id", actID, "by", approver)
		writeJSON(w, map[string]any{"id": actID, "status": model.ActionPending})
		return
	}
	ok, err := s.store.RejectAction(r.Context(), actID, approver)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "action is not awaiting approval", http.StatusConflict)
		return
	}
	s.store.InsertServerEvent(r.Context(), org, act.EndpointID, "action_rejected",
		fmt.Sprintf("%s rejected response action: %s", approver, detail))
	s.audit(r, "action.reject."+act.Type, org, detail+" on "+act.EndpointID)
	writeJSON(w, map[string]any{"id": actID, "status": model.ActionRejected})
}

func (s *Server) handleApproveAction(w http.ResponseWriter, r *http.Request) {
	s.handleActionDecision(w, r, true)
}
func (s *Server) handleRejectAction(w http.ResponseWriter, r *http.Request) {
	s.handleActionDecision(w, r, false)
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
