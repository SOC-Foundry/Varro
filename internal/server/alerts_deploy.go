package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

const (
	deployWindow     = 6 * time.Minute // before/after comparison window
	deployMaxAge     = 30 * time.Minute
	deployMinReqs    = 10   // need enough requests each side to compare
	deployErrJumpPP  = 0.05 // error rate up by >5 percentage points → regression
	deployP95Factor  = 1.5  // p95 up by >1.5x (and over a floor) → regression
	deployP95FloorMs = 150
)

// deployWatch correlates recent CI/CD deploys with service regressions: for each
// settled deploy (its after-window is complete), it compares the deployed
// service's error rate and p95 before vs after the deploy and, on a clear
// regression, raises a deploy-regression event + alert. `seen` dedupes by event
// id across ticks (the caller owns it; the alert loop is single-goroutine).
func (s *Server) deployWatch(ctx context.Context, seen map[int64]bool) {
	evs, err := s.store.Events(ctx, "", nil, 300)
	if err != nil {
		return
	}
	now := time.Now()
	for _, e := range evs {
		if e.Type != model.EventCICD || seen[e.ID] {
			continue
		}
		age := now.Sub(e.Timestamp)
		if age < deployWindow || age > deployMaxAge {
			continue // after-window not complete yet, or too old
		}
		seen[e.ID] = true
		service := strings.TrimPrefix(e.EndpointID, "ci/")
		if service == "" || service == "unknown" {
			continue
		}
		t := e.Timestamp.Unix()
		before := serviceIn(ctx, s, e.OrgID, t-int64(deployWindow.Seconds()), t, service)
		after := serviceIn(ctx, s, e.OrgID, t, t+int64(deployWindow.Seconds()), service)
		if before == nil || after == nil || before.Requests < deployMinReqs || after.Requests < deployMinReqs {
			continue // not enough signal to judge
		}

		reasons := deployRegressionReasons(*before, *after)
		if len(reasons) == 0 {
			continue
		}
		msg := fmt.Sprintf("deploy of %s likely caused a regression: %s", service, strings.Join(reasons, ", "))
		s.store.InsertServerEvent(ctx, e.OrgID, "ci/"+service, model.EventDeployRegression, msg)
		ep := model.EndpointSummary{ID: "svc/" + e.OrgID + "/" + service, Hostname: service, OrgID: e.OrgID}
		s.setAlertState(ctx, "deploy-regression", ep, true, after.ErrorRate*100, msg)
		s.siemForward(e.OrgID, service, model.EventDeployRegression, "WARNING", "", msg)
		s.log.Warn("deploy regression", "service", service, "reasons", strings.Join(reasons, ", "))
	}
}

// deployRegressionReasons returns the human-readable regression drivers when a
// service's error rate or p95 latency clearly worsened after a deploy; empty
// means no regression.
func deployRegressionReasons(before, after model.ServiceHealth) []string {
	var reasons []string
	if after.ErrorRate-before.ErrorRate > deployErrJumpPP {
		reasons = append(reasons, fmt.Sprintf("error rate %.1f%%→%.1f%%", before.ErrorRate*100, after.ErrorRate*100))
	}
	if after.P95Ms > before.P95Ms*deployP95Factor && after.P95Ms > deployP95FloorMs {
		reasons = append(reasons, fmt.Sprintf("p95 %.0fms→%.0fms", before.P95Ms, after.P95Ms))
	}
	return reasons
}

// serviceIn returns one service's RED health in [from, to), or nil if absent.
func serviceIn(ctx context.Context, s *Server, org string, from, to int64, service string) *model.ServiceHealth {
	hs, err := s.store.OTLPServiceHealthRange(ctx, []string{org}, from, to, int(deployWindow/time.Minute))
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
