package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/soc-foundry/varro/internal/model"
	"github.com/soc-foundry/varro/internal/store"
)

// maxLogBody bounds one log-ingest batch.
const maxLogBody = 8 << 20

// handleLogIngest accepts a batch of log lines from an authenticated agent and
// stores them under that agent's endpoint and org.
func (s *Server) handleLogIngest(w http.ResponseWriter, r *http.Request) {
	agentID, orgID, ok := s.agentAuthorized(r)
	if !ok || agentID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var entries []model.LogEntry
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLogBody))
	if err := dec.Decode(&entries); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.InsertLogs(r.Context(), orgID, agentID, entries); err != nil {
		s.log.Error("log ingest failed", "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleLogs serves a filtered, newest-first log search (read-scoped).
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	minutes := 60
	if m := q.Get("minutes"); m != "" {
		if v, err := strconv.Atoi(m); err == nil && v > 0 && v <= 10080 {
			minutes = v
		}
	}
	limit := 200
	if l := q.Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 2000 {
			limit = v
		}
	}
	logs, err := s.store.QueryLogs(r.Context(), store.LogQuery{
		OrgIDs:     scope,
		EndpointID: q.Get("endpoint"),
		Severity:   q.Get("severity"),
		Text:       q.Get("q"),
		Since:      time.Now().Add(-time.Duration(minutes) * time.Minute).Unix(),
		Limit:      limit,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if logs == nil {
		logs = []model.StoredLog{}
	}
	writeJSON(w, map[string]any{"minutes": minutes, "logs": logs})
}
