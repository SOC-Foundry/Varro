package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/soc-foundry/varro/internal/model"
)

// viewOwner is the key saved views are scoped to — the signed-in user's email,
// or "" in open (lab) mode where there's a single shared bucket.
func (s *Server) viewOwner(r *http.Request) string {
	if u, ok := s.currentUser(r); ok {
		return u.Email
	}
	return ""
}

func (s *Server) handleListViews(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireReadScope(w, r); !ok {
		return
	}
	views, err := s.store.ListViews(r.Context(), s.viewOwner(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if views == nil {
		views = []model.SavedView{}
	}
	writeJSON(w, map[string]any{"views": views})
}

func (s *Server) handleSaveView(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
		Spec string `json:"spec"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil ||
		req.Name == "" || req.Spec == "" {
		http.Error(w, "need {\"name\":..., \"spec\":...}", http.StatusBadRequest)
		return
	}
	orgID := ""
	if len(scope) > 0 {
		orgID = scope[0]
	}
	if err := s.store.SaveView(r.Context(), s.viewOwner(r), orgID, req.Name, req.Spec); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"saved": true})
}

func (s *Server) handleDeleteView(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireReadScope(w, r); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	removed, err := s.store.DeleteView(r.Context(), s.viewOwner(r), id)
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
