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

// sloEvaluate turns a service's health over the SLO window into an error-budget
// status. Pure/testable.
func sloEvaluate(slo model.SLO, h *model.ServiceHealth) model.SLOStatus {
	st := model.SLOStatus{Service: slo.Service, Target: slo.Target, WindowMinutes: slo.WindowMinutes}
	if h == nil || h.Requests == 0 {
		st.Status = "no-data"
		return st
	}
	st.Requests, st.Errors, st.ErrorRate = h.Requests, h.Errors, h.ErrorRate
	budget := 1 - slo.Target // allowed error rate
	if budget <= 0 {
		budget = 1e-9
	}
	st.BudgetConsumed = h.ErrorRate / budget
	switch {
	case st.BudgetConsumed >= 1:
		st.Status = "breached"
	case st.BudgetConsumed >= 0.75:
		st.Status = "warning"
	default:
		st.Status = "ok"
	}
	return st
}

// serviceHealth returns one service's RED health over a window for an org (nil if
// the service has no traces in the window).
func (s *Server) serviceHealth(ctx context.Context, orgID, service string, windowMin int) *model.ServiceHealth {
	if windowMin < 1 {
		windowMin = 60
	}
	since := time.Now().Add(-time.Duration(windowMin) * time.Minute).Unix()
	hs, err := s.store.OTLPServiceHealth(ctx, []string{orgID}, since, windowMin)
	if err != nil {
		return nil
	}
	for i := range hs {
		if hs[i].Service == service {
			return &hs[i]
		}
	}
	return nil
}

// sloStatuses evaluates every SLO in scope against current trace data.
func (s *Server) sloStatuses(ctx context.Context, scope []string) []model.SLOStatus {
	slos, err := s.store.SLOsForOrgs(ctx, scope)
	if err != nil {
		s.log.Error("slo: list", "error", err)
		return nil
	}
	out := make([]model.SLOStatus, 0, len(slos))
	for _, slo := range slos {
		out = append(out, sloEvaluate(slo, s.serviceHealth(ctx, slo.OrgID, slo.Service, slo.WindowMinutes)))
	}
	return out
}

// handleSLOList returns current SLO statuses for the request's read scope.
func (s *Server) handleSLOList(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{"slos": s.sloStatuses(r.Context(), scope)})
}

// handleSLOCreate upserts a service SLO (org admin).
func (s *Server) handleSLOCreate(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	var req struct {
		Service       string  `json:"service"`
		Target        float64 `json:"target"`
		WindowMinutes int     `json:"window_minutes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Service = strings.TrimSpace(req.Service)
	if req.Service == "" {
		http.Error(w, "service is required", http.StatusBadRequest)
		return
	}
	if req.Target <= 0 || req.Target >= 1 {
		http.Error(w, "target must be between 0 and 1 (e.g. 0.999)", http.StatusBadRequest)
		return
	}
	if req.WindowMinutes < 1 || req.WindowMinutes > 10080 {
		req.WindowMinutes = 1440 // default 24h
	}
	if err := s.store.UpsertSLO(r.Context(), model.SLO{OrgID: orgID, Service: req.Service, Target: req.Target, WindowMinutes: req.WindowMinutes}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "slo.set", orgID, req.Service)
	writeJSON(w, map[string]bool{"ok": true})
}

// handleSLODelete removes a service SLO (org admin).
func (s *Server) handleSLODelete(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteSLO(r.Context(), orgID, r.PathValue("service")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "slo.delete", orgID, r.PathValue("service"))
	writeJSON(w, map[string]bool{"removed": true})
}

// sloLoop raises an alert when a service exhausts its SLO error budget. Leader
// only, every 10 minutes, rate-limited hourly per service.
func (s *Server) sloLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !s.isLeader() {
				continue
			}
			slos, err := s.store.SLOsForOrgs(ctx, nil)
			if err != nil {
				continue
			}
			for _, slo := range slos {
				st := sloEvaluate(slo, s.serviceHealth(ctx, slo.OrgID, slo.Service, slo.WindowMinutes))
				if st.Status != "breached" || !s.driftShouldAlert("slo|"+slo.OrgID+"|"+slo.Service, time.Hour) {
					continue
				}
				msg := fmt.Sprintf("SLO breach: service %s error rate %.2f%% exhausted its %.3g%% error budget over %dm (%d/%d failed)",
					slo.Service, st.ErrorRate*100, (1-slo.Target)*100, slo.WindowMinutes, st.Errors, st.Requests)
				if err := s.store.InsertServerEvent(ctx, slo.OrgID, "otlp/"+slo.Service, model.EventSLOBreach, msg); err != nil {
					continue
				}
				s.log.Warn("SLO breach", "org", slo.OrgID, "service", slo.Service, "error_rate", st.ErrorRate)
				s.notifyEvents(slo.OrgID, slo.Service, []model.Event{{Type: model.EventSLOBreach, Message: msg}})
				s.siemForward(slo.OrgID, slo.Service, model.EventSLOBreach, "HIGH", "", msg)
			}
		}
	}
}
