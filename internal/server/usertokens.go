package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/soc-foundry/varro/internal/model"
)

// handleListUserTokens lists the caller's personal API tokens (labels only).
func (s *Server) handleListUserTokens(w http.ResponseWriter, r *http.Request) {
	u, ok := s.currentUser(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	toks, err := s.store.UserTokenInfos(r.Context(), u.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if toks == nil {
		toks = []model.UserTokenInfo{}
	}
	writeJSON(w, toks)
}

// handleCreateUserToken mints a personal API token for the caller. The plaintext
// is returned exactly once; only its hash is stored. The token inherits the
// caller's current scope on every request, so revoking the user's access (admin
// or org membership) narrows the token immediately.
func (s *Server) handleCreateUserToken(w http.ResponseWriter, r *http.Request) {
	u, ok := s.currentUser(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) // name optional
	name := strings.TrimSpace(req.Name)
	if len(name) > 100 {
		name = name[:100]
	}
	token, id, err := s.store.CreateUserToken(r.Context(), u.ID, u.Email, name, hashToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.Info("personal API token minted", "user", u.Email, "token_id", id, "name", name)
	s.audit(r, "api_token.mint", "", "minted personal API token "+name)
	writeJSON(w, map[string]string{"id": id, "token": token})
}

// handleRevokeUserToken revokes one of the caller's personal API tokens by id.
func (s *Server) handleRevokeUserToken(w http.ResponseWriter, r *http.Request) {
	u, ok := s.currentUser(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	removed, err := s.store.DeleteUserToken(r.Context(), u.ID, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, "unknown token", http.StatusNotFound)
		return
	}
	s.log.Info("personal API token revoked", "user", u.Email, "token_id", id)
	s.audit(r, "api_token.revoke", "", "revoked personal API token "+id)
	writeJSON(w, map[string]string{"status": "revoked"})
}
