package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/soc-foundry/varro/internal/model"
)

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// handleMe tells the dashboard who is signed in and which orgs they can see.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	type meResponse struct {
		AuthEnabled bool        `json:"auth_enabled"`
		User        *model.User `json:"user,omitempty"`
		Orgs        []model.Org `json:"orgs"`
	}
	resp := meResponse{AuthEnabled: s.AuthEnabled(), Orgs: []model.Org{}}

	if !s.AuthEnabled() {
		orgs, err := s.store.Orgs(r.Context())
		if err == nil {
			resp.Orgs = orgs
		}
		writeJSON(w, resp)
		return
	}

	user, ok := s.sessionUser(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	resp.User = &user
	if user.Admin {
		if orgs, err := s.store.Orgs(r.Context()); err == nil {
			resp.Orgs = orgs
		}
	} else if orgs, err := s.store.UserOrgs(r.Context(), user.Email); err == nil {
		resp.Orgs = orgs
	}
	writeJSON(w, resp)
}

// handleOrgsList lists all orgs (admin only).
func (s *Server) handleOrgsList(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	orgs, err := s.store.Orgs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if orgs == nil {
		orgs = []model.Org{}
	}
	writeJSON(w, orgs)
}

// handleOrgCreate creates a new org (admin only).
func (s *Server) handleOrgCreate(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil ||
		strings.TrimSpace(req.Name) == "" {
		http.Error(w, "bad request: need {\"name\": ...}", http.StatusBadRequest)
		return
	}
	org, err := s.store.CreateOrg(r.Context(), strings.TrimSpace(req.Name))
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.log.Info("org created", "org", org.ID, "name", org.Name)
	writeJSON(w, org)
}

// handleOrgToken mints an enrollment token for an org (admin only). The
// plaintext token is returned once and never stored.
func (s *Server) handleOrgToken(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	org, err := s.store.OrgByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) // name is optional

	token, err := s.store.CreateOrgToken(r.Context(), org.ID, req.Name, hashToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.Info("org enrollment token minted", "org", org.ID, "token_name", req.Name)
	writeJSON(w, map[string]string{"org_id": org.ID, "token": token})
}

// handleOrgInvite adds a member to an org by email (admin only).
func (s *Server) handleOrgInvite(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	org, err := s.store.OrgByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil ||
		!strings.Contains(req.Email, "@") {
		http.Error(w, "bad request: need {\"email\": ...}", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if err := s.store.AddOrgMember(r.Context(), org.ID, email, req.Role); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.Info("org member added", "org", org.ID, "email", email)
	writeJSON(w, map[string]string{"org_id": org.ID, "email": email})
}
