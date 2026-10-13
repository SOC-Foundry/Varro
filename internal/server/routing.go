package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

var sevRank = map[string]int{
	model.SevInfo:     0,
	model.SevWarning:  1,
	model.SevCritical: 2,
}

// alertSeverity maps an alert transition to a routing severity.
func alertSeverity(state, rule string) string {
	if state == "resolved" {
		return model.SevInfo
	}
	switch rule {
	case "synthetic-down", "service-error-rate", "service-latency-p95":
		return model.SevCritical
	}
	return model.SevWarning
}

// eventSeverity maps a security event type to a routing severity.
func eventSeverity(evType string) string {
	switch evType {
	case model.EventThreatMatch, model.EventMalwareMatch, model.EventDomainThreatMatch,
		model.EventDetection, model.EventDeployRegression:
		return model.SevCritical
	}
	return model.SevWarning
}

// dispatchRoutes fans one notification out to an org's enabled routes whose
// MinSeverity the alert meets. Additive to the global webhook/Slack/email config.
func (s *Server) dispatchRoutes(orgID, severity, state, rule, hostname, message string) {
	if orgID == "" {
		return
	}
	ctx := context.Background()
	routes, err := s.store.EnabledNotifyRoutes(ctx, orgID)
	if err != nil || len(routes) == 0 {
		return
	}
	infra, _ := s.store.OrgIsInfrastructure(ctx, orgID)
	want := sevRank[severity]
	for _, rt := range routes {
		if sevRank[rt.MinSeverity] > want {
			continue
		}
		go s.sendRoute(rt, infra, severity, state, rule, hostname, message)
	}
}

// guardedClient builds an HTTP client whose dialer blocks SSRF to internal
// addresses (same policy as synthetic probes) — org-configured webhook/Slack
// URLs are semi-trusted tenant input.
func (s *Server) guardedClient(infra bool) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: probeDialControl(infra)}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true},
	}
}

func (s *Server) sendRoute(rt model.NotifyRoute, infra bool, severity, state, rule, hostname, message string) {
	text := fmt.Sprintf("[varro] %s · %s · %s — %s", strings.ToUpper(state), rule, hostname, message)
	switch rt.Type {
	case model.RouteWebhook:
		s.postRoute(s.guardedClient(infra), rt.Target, nil, map[string]string{
			"org": rt.OrgID, "severity": severity, "state": state,
			"rule": rule, "hostname": hostname, "message": message,
		})
	case model.RouteSlack:
		s.postRoute(s.guardedClient(infra), rt.Target, nil, map[string]string{"text": text})
	case model.RoutePagerDuty:
		s.sendPagerDuty(rt, severity, state, rule, hostname, message)
	case model.RouteOpsgenie:
		s.sendOpsgenie(rt, severity, state, rule, hostname, message)
	}
}

// sendPagerDuty uses the Events API v2: firing → trigger, resolved → resolve,
// correlated by a dedup key of rule+host.
func (s *Server) sendPagerDuty(rt model.NotifyRoute, severity, state, rule, hostname, message string) {
	action := "trigger"
	if state == "resolved" {
		action = "resolve"
	}
	pdSev := severity // PD accepts info|warning|error|critical
	payload := map[string]any{
		"routing_key":  rt.Target,
		"event_action": action,
		"dedup_key":    "varro/" + rule + "/" + hostname,
		"payload": map[string]any{
			"summary":   message,
			"source":    hostname,
			"severity":  pdSev,
			"component": rule,
		},
	}
	// The default client is fine: a fixed, public SaaS host.
	s.postRoute(http.DefaultClient, "https://events.pagerduty.com/v2/enqueue", nil, payload)
}

// sendOpsgenie uses the Alerts API: firing → create, resolved → close (by alias).
func (s *Server) sendOpsgenie(rt model.NotifyRoute, severity, state, rule, hostname, message string) {
	alias := "varro/" + rule + "/" + hostname
	hdr := map[string]string{"Authorization": "GenieKey " + rt.Target}
	if state == "resolved" {
		s.postRoute(http.DefaultClient,
			"https://api.opsgenie.com/v2/alerts/"+url.PathEscape(alias)+"/close?identifierType=alias",
			hdr, map[string]any{"source": "varro"})
		return
	}
	prio := "P3"
	if severity == model.SevCritical {
		prio = "P1"
	}
	s.postRoute(http.DefaultClient, "https://api.opsgenie.com/v2/alerts", hdr, map[string]any{
		"message":     fmt.Sprintf("%s: %s", hostname, rule),
		"alias":       alias,
		"description": message,
		"priority":    prio,
		"source":      "varro",
	})
}

// postRoute POSTs a JSON payload with optional headers, logging non-2xx.
func (s *Server) postRoute(client *http.Client, url string, headers map[string]string, payload any) {
	body, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		s.log.Error("route notify failed", "url", redactURL(url), "error", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		s.log.Error("route notify rejected", "url", redactURL(url), "status", resp.Status)
	}
}

// redactURL reduces a URL to scheme://host for logging — webhook/Slack URLs
// embed secret tokens in their path, which must never reach the logs.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "[redacted]"
	}
	return u.Scheme + "://" + u.Host
}

// ---- handlers ----

func (s *Server) handleOrgRoutes(w http.ResponseWriter, r *http.Request) {
	org, err := s.store.OrgByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !s.orgAdminAuthorized(r, org.ID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	routes, err := s.store.NotifyRoutes(r.Context(), org.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if routes == nil {
		routes = []model.NotifyRoute{}
	}
	writeJSON(w, map[string]any{"routes": routes})
}

func (s *Server) handleOrgRouteCreate(w http.ResponseWriter, r *http.Request) {
	org, err := s.store.OrgByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !s.orgAdminAuthorized(r, org.ID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Type        string `json:"type"`
		Target      string `json:"target"`
		MinSeverity string `json:"min_severity"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	route, err := validateRoute(req.Type, req.Target, req.MinSeverity)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	route.OrgID = org.ID
	route.Enabled = true
	created, err := s.store.CreateNotifyRoute(r.Context(), route)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "route.create", org.ID, created.Type+" "+created.MinSeverity)
	writeJSON(w, created)
}

func (s *Server) handleOrgRouteDelete(w http.ResponseWriter, r *http.Request) {
	org, err := s.store.OrgByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !s.orgAdminAuthorized(r, org.ID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	removed, err := s.store.DeleteNotifyRoute(r.Context(), org.ID, r.PathValue("routeID"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.audit(r, "route.delete", org.ID, r.PathValue("routeID"))
	writeJSON(w, map[string]bool{"removed": true})
}

// validateRoute normalizes and validates a route request.
func validateRoute(typ, target, minSev string) (model.NotifyRoute, error) {
	rt := model.NotifyRoute{}
	target = strings.TrimSpace(target)
	if target == "" {
		return rt, fmt.Errorf("target is required")
	}
	switch typ {
	case model.RouteWebhook, model.RouteSlack:
		u, err := url.Parse(target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return rt, fmt.Errorf("%s target must be an http(s) URL", typ)
		}
	case model.RoutePagerDuty, model.RouteOpsgenie:
		// Target is an integration/routing/API key; no URL.
	default:
		return rt, fmt.Errorf("type must be webhook, slack, pagerduty, or opsgenie")
	}
	switch minSev {
	case "":
		minSev = model.SevWarning
	case model.SevInfo, model.SevWarning, model.SevCritical:
	default:
		return rt, fmt.Errorf("min_severity must be info, warning, or critical")
	}
	rt.Type, rt.Target, rt.MinSeverity = typ, target, minSev
	return rt, nil
}
