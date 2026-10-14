package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// digestLoop sends due per-org report digests (leader-only). Checks hourly;
// each schedule fires on its own daily/weekly cadence.
func (s *Server) digestLoop(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !s.isLeader() || !s.mailEnabled() {
				continue
			}
			due, err := s.store.DueReportSchedules(ctx)
			if err != nil {
				s.log.Error("digest: list due schedules", "error", err)
				continue
			}
			for _, sc := range due {
				subj, body := s.composeDigest(ctx, sc.OrgID)
				s.sendMailTo(sc.Recipients, subj, body)
				if err := s.store.MarkReportSent(ctx, sc.OrgID, time.Now()); err != nil {
					s.log.Error("digest: mark sent", "org", sc.OrgID, "error", err)
				}
				s.log.Info("report digest sent", "org", sc.OrgID, "recipients", len(sc.Recipients))
			}
		}
	}
}

// composeDigest builds the subject + plaintext body of an org's digest.
func (s *Server) composeDigest(ctx context.Context, orgID string) (string, string) {
	name := orgID
	if org, err := s.store.OrgByRef(ctx, orgID); err == nil && org.Name != "" {
		name = org.Name
	}
	rep, _ := s.buildReport(ctx, []string{orgID})
	open, crit, _ := s.store.IncidentCounts(ctx, orgID)

	var b strings.Builder
	fmt.Fprintf(&b, "Varro digest — %s\n%s\n\n", name, time.Now().UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(&b, "Fleet:        %d endpoints (%d online)\n", rep.Endpoints, rep.Online)
	fmt.Fprintf(&b, "Posture:      %d%% passing (%d pass / %d fail)\n", rep.PostureScore, rep.PosturePass, rep.PostureFail)
	fmt.Fprintf(&b, "Vulns:        %d total", rep.VulnTotal)
	if len(rep.Vulns) > 0 {
		var parts []string
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if n := rep.Vulns[sev]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, sev))
			}
		}
		if len(parts) > 0 {
			fmt.Fprintf(&b, " (%s)", strings.Join(parts, ", "))
		}
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "Patching:     %d pending updates, %d need reboot\n", rep.PendingUpdates, rep.RebootRequired)
	fmt.Fprintf(&b, "Services:     %d endpoints with a failed service\n", rep.FailedServices)
	fmt.Fprintf(&b, "Incidents:    %d open (%d critical)\n", open, crit)
	b.WriteString("\n— Varro (https://varro.socfoundry.com)\n")

	subj := fmt.Sprintf("Varro digest — %s — %d open incidents, %d vulns", name, open, rep.VulnTotal)
	return subj, b.String()
}

// ---- handlers (org-admin) ----

func (s *Server) handleReportSchedule(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	sc, err := s.store.ReportSchedule(r.Context(), orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if sc.Recipients == nil {
		sc.Recipients = []string{}
	}
	writeJSON(w, sc)
}

func (s *Server) handleSetReportSchedule(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	var req struct {
		Enabled    bool     `json:"enabled"`
		Cadence    string   `json:"cadence"`
		Recipients []string `json:"recipients"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Cadence != "daily" && req.Cadence != "weekly" {
		req.Cadence = "weekly"
	}
	var recips []string
	for _, e := range req.Recipients {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, err := mail.ParseAddress(e); err != nil {
			http.Error(w, "invalid email: "+e, http.StatusBadRequest)
			return
		}
		recips = append(recips, e)
	}
	if req.Enabled && len(recips) == 0 {
		http.Error(w, "at least one recipient is required to enable digests", http.StatusBadRequest)
		return
	}
	if err := s.store.SetReportSchedule(r.Context(), model.ReportSchedule{
		OrgID: orgID, Enabled: req.Enabled, Cadence: req.Cadence, Recipients: recips,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "report.schedule", orgID, fmt.Sprintf("%s digest to %d recipient(s), enabled=%v", req.Cadence, len(recips), req.Enabled))
	writeJSON(w, map[string]bool{"saved": true})
}
