package server

import (
	"context"
	"fmt"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// Thresholds for the telemetry-derived alerts (SLO + log bursts). Sensible
// defaults; kept as constants for now (host-metric rules stay in the rules file).
const (
	svcAlertWindow  = 5 * time.Minute
	svcMinRequests  = 20     // don't judge SLO on too few requests
	svcErrorRatePct = 5.0    // alert when a service's error rate exceeds this %
	svcLatencyP95Ms = 2000.0 // alert when a service's p95 latency exceeds this
	logBurstWindow  = 5 * time.Minute
	logBurstCount   = 50 // alert when an endpoint logs more than this many error-level lines
)

// evaluateServiceAlerts fires SLO alerts (error rate, p95 latency) per traced
// service, scoped per org, from the RED aggregates.
func (s *Server) evaluateServiceAlerts(ctx context.Context) {
	orgs, err := s.store.Orgs(ctx)
	if err != nil {
		return
	}
	mins := int(svcAlertWindow / time.Minute)
	since := time.Now().Add(-svcAlertWindow).Unix()
	for _, org := range orgs {
		svcs, err := s.store.OTLPServiceHealth(ctx, []string{org.ID}, since, mins)
		if err != nil {
			continue
		}
		for _, h := range svcs {
			if h.Requests < svcMinRequests {
				continue
			}
			ep := model.EndpointSummary{ID: "svc/" + org.ID + "/" + h.Service, Hostname: h.Service, OrgID: org.ID}
			erPct := h.ErrorRate * 100
			s.setAlertState(ctx, "service-error-rate", ep, erPct > svcErrorRatePct, erPct,
				fmt.Sprintf("service %s error rate %.1f%% over %s (threshold %.0f%%, %d reqs)",
					h.Service, erPct, svcAlertWindow, svcErrorRatePct, h.Requests))
			s.setAlertState(ctx, "service-latency-p95", ep, h.P95Ms > svcLatencyP95Ms, h.P95Ms,
				fmt.Sprintf("service %s p95 latency %.0fms over %s (threshold %.0fms)",
					h.Service, h.P95Ms, svcAlertWindow, svcLatencyP95Ms))
		}
	}
}

// evaluateLogAlerts fires a log-burst alert per endpoint producing an unusual
// number of error-level log lines. Iterates all endpoints so recovered ones
// resolve cleanly.
func (s *Server) evaluateLogAlerts(ctx context.Context) {
	eps, err := s.store.Endpoints(ctx, nil)
	if err != nil {
		return
	}
	since := time.Now().Add(-logBurstWindow).Unix()
	for _, ep := range eps {
		n, err := s.store.LogErrorCount(ctx, ep.ID, since)
		if err != nil {
			continue
		}
		s.setAlertState(ctx, "log-error-burst", ep, n > logBurstCount, float64(n),
			fmt.Sprintf("%s logged %d error-level lines in %s (threshold %d)",
				ep.Hostname, n, logBurstWindow, logBurstCount))
	}
}
