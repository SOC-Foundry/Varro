package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/soc-foundry/varro/internal/model"
)

func (s *Server) handleListDashboards(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireReadScope(w, r); !ok {
		return
	}
	dashes, err := s.store.ListDashboards(r.Context(), s.viewOwner(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if dashes == nil {
		dashes = []model.Dashboard{}
	}
	writeJSON(w, map[string]any{"dashboards": dashes})
}

func (s *Server) handleSaveDashboard(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
		Spec string `json:"spec"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil ||
		req.Name == "" || req.Spec == "" {
		http.Error(w, "need {\"name\":..., \"spec\":...}", http.StatusBadRequest)
		return
	}
	// Spec must be valid JSON (opaque otherwise).
	if !json.Valid([]byte(req.Spec)) {
		http.Error(w, "spec must be valid JSON", http.StatusBadRequest)
		return
	}
	orgID := ""
	if len(scope) > 0 {
		orgID = scope[0]
	}
	if err := s.store.SaveDashboard(r.Context(), s.viewOwner(r), orgID, req.Name, req.Spec); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"saved": true})
}

func (s *Server) handleDeleteDashboard(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireReadScope(w, r); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	removed, err := s.store.DeleteDashboard(r.Context(), s.viewOwner(r), id)
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
