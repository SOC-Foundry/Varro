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

// handleMe tells the dashboard who is signed in, which orgs they can see, and
// what they may manage (role "admin" per org, or instance admin everywhere).
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	type orgEntry struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Role string `json:"role"`
	}
	type meResponse struct {
		AuthEnabled bool        `json:"auth_enabled"`
		User        *model.User `json:"user,omitempty"`
		Orgs        []orgEntry  `json:"orgs"`
	}
	resp := meResponse{AuthEnabled: s.AuthEnabled(), Orgs: []orgEntry{}}

	if !s.AuthEnabled() {
		if orgs, err := s.store.Orgs(r.Context()); err == nil {
			for _, o := range orgs {
				resp.Orgs = append(resp.Orgs, orgEntry{o.ID, o.Name, "member"})
			}
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
			for _, o := range orgs {
				resp.Orgs = append(resp.Orgs, orgEntry{o.ID, o.Name, "admin"})
			}
		}
	} else if orgs, err := s.store.UserOrgs(r.Context(), user.Email); err == nil {
		for _, o := range orgs {
			role, _ := s.store.OrgRole(r.Context(), o.ID, user.Email)
			resp.Orgs = append(resp.Orgs, orgEntry{o.ID, o.Name, role})
		}
	}
	writeJSON(w, resp)
}

// freeMailDomains may never be used for auto-join: they are shared by the
// whole world, so claiming one would pull strangers into a tenant.
var freeMailDomains = map[string]bool{
	"gmail.com": true, "googlemail.com": true, "outlook.com": true,
	"hotmail.com": true, "live.com": true, "yahoo.com": true,
	"icloud.com": true, "me.com": true, "aol.com": true,
	"proton.me": true, "protonmail.com": true, "gmx.com": true,
}

// handleOrgUpdate sets org settings — currently the auto-join domain.
// Instance admin only: letting org admins claim domains would allow a tenant
// to capture other organizations' users.
func (s *Server) handleOrgUpdate(w http.ResponseWriter, r *http.Request) {
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
		AutoJoinDomain *string `json:"auto_join_domain"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.AutoJoinDomain == nil {
		http.Error(w, "bad request: need {\"auto_join_domain\": ...}", http.StatusBadRequest)
		return
	}
	domain := strings.ToLower(strings.TrimSpace(*req.AutoJoinDomain))
	if freeMailDomains[domain] {
		http.Error(w, "refusing to auto-join a shared free-mail domain", http.StatusBadRequest)
		return
	}
	if domain != "" && !strings.Contains(domain, ".") {
		http.Error(w, "not a valid domain", http.StatusBadRequest)
		return
	}
	if err := s.store.SetOrgDomain(r.Context(), org.ID, domain); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.Info("org auto-join domain set", "org", org.ID, "domain", domain)
	writeJSON(w, map[string]string{"org_id": org.ID, "auto_join_domain": domain})
}

// handleUserAdmin grants or revokes instance-admin status (instance admin
// only). Demotion is refused for the last remaining admin, for anyone still
// pinned by --admin-emails (sign-in would silently re-promote them), and for
// the caller's own session account.
func (s *Server) handleUserAdmin(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	email := strings.ToLower(r.PathValue("email"))
	var req struct {
		Admin *bool `json:"admin"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Admin == nil {
		http.Error(w, "bad request: need {\"admin\": true|false}", http.StatusBadRequest)
		return
	}

	if !*req.Admin {
		if s.cfg.AdminEmails[email] {
			http.Error(w, "this email is in --admin-emails; remove it from the server flag first or sign-in will re-promote them", http.StatusConflict)
			return
		}
		if user, ok := s.sessionUser(r); ok && user.Email == email {
			http.Error(w, "refusing to demote your own account", http.StatusConflict)
			return
		}
		wasAdmin, exists, err := s.store.UserIsAdmin(r.Context(), email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if exists && wasAdmin {
			n, err := s.store.AdminCount(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if n <= 1 {
				http.Error(w, "refusing to demote the last instance admin", http.StatusConflict)
				return
			}
		}
	}

	exists, err := s.store.SetUserAdmin(r.Context(), email, *req.Admin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "no such user (they must sign in at least once first)", http.StatusNotFound)
		return
	}
	s.log.Info("instance-admin status changed", "email", email, "admin", *req.Admin)
	writeJSON(w, map[string]any{"email": email, "admin": *req.Admin})
}

// handleOrgDelete removes an empty org (instance admin only).
func (s *Server) handleOrgDelete(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	org, err := s.store.OrgByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := s.store.DeleteOrg(r.Context(), org.ID); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.log.Info("org deleted", "org", org.ID, "name", org.Name)
	writeJSON(w, map[string]bool{"deleted": true})
}

// handleOrgMembers lists an org's membership (org admins and up).
func (s *Server) handleOrgMembers(w http.ResponseWriter, r *http.Request) {
	org, err := s.store.OrgByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !s.orgAdminAuthorized(r, org.ID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	members, err := s.store.OrgMembers(r.Context(), org.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if members == nil {
		members = []model.OrgMember{}
	}
	writeJSON(w, members)
}

// handleOrgTokens lists an org's enrollment-token labels (org admins and up).
func (s *Server) handleOrgTokens(w http.ResponseWriter, r *http.Request) {
	org, err := s.store.OrgByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !s.orgAdminAuthorized(r, org.ID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tokens, err := s.store.OrgTokenInfos(r.Context(), org.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if tokens == nil {
		tokens = []model.OrgTokenInfo{}
	}
	writeJSON(w, tokens)
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
		Name           string `json:"name"`
		AutoJoinDomain string `json:"auto_join_domain"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil ||
		strings.TrimSpace(req.Name) == "" {
		http.Error(w, "bad request: need {\"name\": ...}", http.StatusBadRequest)
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.AutoJoinDomain))
	if freeMailDomains[domain] {
		http.Error(w, "refusing to auto-join a shared free-mail domain", http.StatusBadRequest)
		return
	}
	if domain != "" && !strings.Contains(domain, ".") {
		http.Error(w, "not a valid domain", http.StatusBadRequest)
		return
	}
	org, err := s.store.CreateOrg(r.Context(), strings.TrimSpace(req.Name))
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if domain != "" {
		if err := s.store.SetOrgDomain(r.Context(), org.ID, domain); err == nil {
			org.AutoJoinDomain = domain
		}
	}
	s.log.Info("org created", "org", org.ID, "name", org.Name, "auto_join_domain", domain)
	writeJSON(w, org)
}

// handleOrgToken mints an enrollment token for an org (org admins and up).
// The plaintext token is returned once and never stored.
func (s *Server) handleOrgToken(w http.ResponseWriter, r *http.Request) {
	org, err := s.store.OrgByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !s.orgAdminAuthorized(r, org.ID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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

// handleEndpointRemove deletes a decommissioned endpoint and all its data.
// Permitted for admins of the endpoint's org and up. Distinct from token
// revocation, which cuts off ingest but keeps the endpoint and its history.
func (s *Server) handleEndpointRemove(w http.ResponseWriter, r *http.Request) {
	org, err := s.store.EndpointOrg(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if org == "" {
		if !s.adminAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	} else if !s.orgAdminAuthorized(r, org) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	existed, err := s.store.DeleteEndpoint(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !existed {
		http.Error(w, "unknown endpoint", http.StatusNotFound)
		return
	}
	s.log.Info("endpoint removed", "endpoint", r.PathValue("id"))
	writeJSON(w, map[string]bool{"removed": true})
}

// handleOrgRemoveMember drops a member from an org (org admins and up).
func (s *Server) handleOrgRemoveMember(w http.ResponseWriter, r *http.Request) {
	org, err := s.store.OrgByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !s.orgAdminAuthorized(r, org.ID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	email := strings.ToLower(r.PathValue("email"))
	existed, err := s.store.RemoveOrgMember(r.Context(), org.ID, email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !existed {
		http.Error(w, "not a member", http.StatusNotFound)
		return
	}
	s.log.Info("org member removed", "org", org.ID, "email", email)
	writeJSON(w, map[string]bool{"removed": true})
}

// handleOrgInvite adds a member to an org by email (org admins and up).
func (s *Server) handleOrgInvite(w http.ResponseWriter, r *http.Request) {
	org, err := s.store.OrgByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !s.orgAdminAuthorized(r, org.ID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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

	// Automated invitation email when an SMTP relay is configured.
	go s.sendMailTo([]string{email},
		"You've been invited to Varro ("+org.Name+")",
		"You've been granted access to the \""+org.Name+"\" organization on Varro, "+
			"SOC Foundry's endpoint telemetry platform.\r\n\r\n"+
			"Sign in with this Google account at:\r\n\r\n    "+
			strings.TrimSuffix(s.cfg.Google.BaseURL, "/")+"\r\n")

	writeJSON(w, map[string]string{"org_id": org.ID, "email": email})
}
