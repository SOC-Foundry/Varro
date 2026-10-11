package server

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// handleReport returns an org-wide compliance rollup (posture, vulns, patch
// health) for auditing. Read-scoped like the rest of the query API.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	rep, err := s.buildReport(r.Context(), scope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, rep)
}

// buildReport aggregates the latest snapshot of every in-scope endpoint plus the
// vulnerability store into a compliance report.
func (s *Server) buildReport(ctx context.Context, scope []string) (model.ComplianceReport, error) {
	// With no specific org selected (admin "all orgs"), exclude infrastructure
	// orgs so monitoring infra doesn't skew tenant compliance numbers. A
	// specific org selection — even an infra one — is always honored as-is.
	if scope == nil {
		ids, err := s.store.NonInfraOrgIDs(ctx)
		if err != nil {
			return model.ComplianceReport{}, err
		}
		// A non-nil empty slice would render as `IN ()` (invalid on Postgres);
		// use a sentinel that matches no org so the report is simply empty.
		if len(ids) == 0 {
			ids = []string{""}
		}
		scope = ids
	}
	eps, err := s.store.Endpoints(ctx, scope)
	if err != nil {
		return model.ComplianceReport{}, err
	}
	rep := model.ComplianceReport{
		GeneratedAt: time.Now().UTC(),
		Endpoints:   len(eps),
		OSBreakdown: map[string]int{},
	}
	// Aggregate posture + health per check across the fleet's latest snapshots.
	type ps struct {
		desc       string
		pass, fail int
	}
	checks := map[string]*ps{}
	for _, ep := range eps {
		if ep.Online {
			rep.Online++
		}
		if ep.OS != "" {
			rep.OSBreakdown[ep.OS]++
		}
		snap, err := s.store.Latest(ctx, ep.ID)
		if err != nil || snap == nil {
			continue
		}
		for _, p := range snap.Posture {
			st := checks[p.ID]
			if st == nil {
				st = &ps{desc: p.Desc}
				checks[p.ID] = st
			}
			switch p.Status {
			case model.PosturePass:
				st.pass++
				rep.PosturePass++
			case model.PostureFail:
				st.fail++
				rep.PostureFail++
			}
		}
		rep.PendingUpdates += snap.Health.PendingUpdates
		if snap.Health.RebootRequired {
			rep.RebootRequired++
		}
		if len(snap.Health.FailedServices) > 0 {
			rep.FailedServices++
		}
	}
	for id, st := range checks {
		rep.PostureChecks = append(rep.PostureChecks, model.PostureStat{
			ID: id, Desc: st.desc, Pass: st.pass, Fail: st.fail,
		})
	}
	// Worst checks first (most failures), then by id for stability.
	sort.Slice(rep.PostureChecks, func(i, j int) bool {
		if rep.PostureChecks[i].Fail != rep.PostureChecks[j].Fail {
			return rep.PostureChecks[i].Fail > rep.PostureChecks[j].Fail
		}
		return rep.PostureChecks[i].ID < rep.PostureChecks[j].ID
	})
	if tot := rep.PosturePass + rep.PostureFail; tot > 0 {
		rep.PostureScore = rep.PosturePass * 100 / tot
	}

	rawVulns, err := s.store.VulnSeverityCounts(ctx, scope)
	if err != nil {
		return rep, err
	}
	// Fold raw severities (qualitative labels or CVSS vectors) into standard
	// buckets so the rollup is meaningful rather than one row per CVSS vector.
	rep.Vulns = map[string]int{}
	for raw, n := range rawVulns {
		rep.Vulns[normalizeSeverity(raw)] += n
		rep.VulnTotal += n
	}
	return rep, nil
}
