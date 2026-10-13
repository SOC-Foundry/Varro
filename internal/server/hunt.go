package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
	"github.com/soc-foundry/varro/internal/store"
)

const huntAlertWindow = 5 * time.Minute

// handleHunt runs a unified, ad-hoc search across security events and logs.
func (s *Server) handleHunt(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	text := strings.TrimSpace(q.Get("q"))
	source := q.Get("source")
	if source == "" {
		source = "all"
	}
	severity := q.Get("severity")
	endpoint := q.Get("endpoint")
	minutes, _ := strconv.Atoi(q.Get("minutes"))
	if minutes <= 0 {
		minutes = 1440
	}
	if minutes > 30*24*60 {
		minutes = 30 * 24 * 60
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	since := time.Now().Add(-time.Duration(minutes) * time.Minute).Unix()

	results := s.huntSearch(r.Context(), scope, source, text, severity, endpoint, since, limit)
	if results == nil {
		results = []model.HuntResult{}
	}
	writeJSON(w, map[string]any{"results": results, "count": len(results)})
}

// huntSearch merges events + logs into a unified, time-sorted result set.
func (s *Server) huntSearch(ctx context.Context, scope []string, source, text, severity, endpoint string, since int64, limit int) []model.HuntResult {
	var results []model.HuntResult
	if source == "all" || source == "events" {
		if evs, err := s.store.SearchEvents(ctx, scope, text, "", since, limit); err == nil {
			for _, e := range evs {
				if endpoint != "" && e.EndpointID != endpoint {
					continue
				}
				results = append(results, model.HuntResult{
					Source: "event", TS: e.Timestamp.Unix(), EndpointID: e.EndpointID,
					Hostname: e.Hostname, Kind: e.Type, Message: e.Message,
				})
			}
		}
	}
	if source == "all" || source == "logs" {
		if logs, err := s.store.QueryLogs(ctx, store.LogQuery{
			OrgIDs: scope, EndpointID: endpoint, Severity: severity, Text: text, Since: since, Limit: limit,
		}); err == nil {
			for _, l := range logs {
				results = append(results, model.HuntResult{
					Source: "log", TS: l.TS, EndpointID: l.EndpointID,
					Hostname: l.Hostname, Kind: l.Severity, Message: l.Message,
				})
			}
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].TS > results[j].TS })
	if len(results) > limit {
		results = results[:limit]
	}
	return results
}

// ---- saved hunts (owner-scoped, like saved views) ----

func (s *Server) handleListHunts(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireReadScope(w, r); !ok {
		return
	}
	hunts, err := s.store.ListHunts(r.Context(), s.viewOwner(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if hunts == nil {
		hunts = []model.Hunt{}
	}
	writeJSON(w, map[string]any{"hunts": hunts})
}

func (s *Server) handleSaveHunt(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	var h model.Hunt
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&h); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	h.Name = strings.TrimSpace(h.Name)
	if h.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	switch h.Source {
	case "", "all":
		h.Source = "all"
	case "events", "logs":
	default:
		http.Error(w, "source must be all, events, or logs", http.StatusBadRequest)
		return
	}
	if h.Threshold < 1 {
		h.Threshold = 1
	}
	orgID := ""
	if len(scope) > 0 {
		orgID = scope[0]
	}
	if h.Alerting && orgID == "" {
		http.Error(w, "alerting hunts require a single-org scope", http.StatusBadRequest)
		return
	}
	if err := s.store.SaveHunt(r.Context(), s.viewOwner(r), orgID, h); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"saved": true})
}

func (s *Server) handleDeleteHunt(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireReadScope(w, r); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	removed, err := s.store.DeleteHunt(r.Context(), s.viewOwner(r), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]bool{"removed": true})
}

// evaluateHuntAlerts fires an alert for each alerting hunt whose match count over
// the last window meets its threshold. Runs leader-only from the alert loop.
func (s *Server) evaluateHuntAlerts(ctx context.Context) {
	hunts, err := s.store.AlertingHunts(ctx)
	if err != nil {
		return
	}
	since := time.Now().Add(-huntAlertWindow).Unix()
	for _, h := range hunts {
		if h.OrgID == "" || h.Threshold < 1 {
			continue
		}
		n := len(s.huntSearch(ctx, []string{h.OrgID}, h.Source, h.Query, h.Severity, "", since, 500))
		ep := model.EndpointSummary{ID: "hunt/" + h.OrgID + "/" + strconv.FormatInt(h.ID, 10), Hostname: h.Name, OrgID: h.OrgID}
		s.setAlertState(ctx, "hunt:"+h.Name, ep, n >= h.Threshold, float64(n),
			fmt.Sprintf("hunt %q matched %d events/logs in %s (threshold %d)", h.Name, n, huntAlertWindow, h.Threshold))
	}
}
