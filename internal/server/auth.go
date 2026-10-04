package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// Google OAuth2 / OIDC endpoints.
const (
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserinfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

	sessionCookie = "varro_session"
	stateCookie   = "varro_oauth_state"
	sessionTTL    = 7 * 24 * time.Hour
)

type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	BaseURL      string // externally visible base URL, e.g. https://varro.example.com
}

// AuthEnabled reports whether dashboard/API sign-in is required. When false
// the instance runs open (lab mode), exactly as before multi-tenancy.
func (s *Server) AuthEnabled() bool { return s.cfg.Google.ClientID != "" }

func (s *Server) redirectURI() string {
	return strings.TrimSuffix(s.cfg.Google.BaseURL, "/") + "/auth/callback"
}

func (s *Server) secureCookies() bool {
	return strings.HasPrefix(s.cfg.Google.BaseURL, "https://")
}

// handleLogin starts the Google authorization-code flow.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.AuthEnabled() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	state, err := randomToken()
	if err != nil {
		http.Error(w, "entropy error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie, Value: state, Path: "/",
		MaxAge: 600, HttpOnly: true, Secure: s.secureCookies(), SameSite: http.SameSiteLaxMode,
	})
	q := url.Values{
		"client_id":     {s.cfg.Google.ClientID},
		"redirect_uri":  {s.redirectURI()},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
	}
	http.Redirect(w, r, googleAuthURL+"?"+q.Encode(), http.StatusFound)
}

// handleCallback finishes the flow: code -> tokens -> verified identity ->
// session cookie.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if !s.AuthEnabled() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	stateC, err := r.Cookie(stateCookie)
	if err != nil || stateC.Value == "" || r.URL.Query().Get("state") != stateC.Value {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/", MaxAge: -1})

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	info, err := s.googleIdentity(r.Context(), code)
	if err != nil {
		s.log.Error("google auth failed", "error", err)
		http.Error(w, "authentication failed", http.StatusBadGateway)
		return
	}
	if !info.EmailVerified {
		http.Error(w, "google account email is not verified", http.StatusForbidden)
		return
	}

	email := strings.ToLower(info.Email)
	user, err := s.store.UpsertGoogleUser(r.Context(), info.Sub, email, info.Name, s.cfg.AdminEmails[email])
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	// Domain auto-join: an org that claims this email's domain automatically
	// gains the user as a member on sign-in.
	if at := strings.LastIndex(email, "@"); at >= 0 {
		domain := email[at+1:]
		if orgID, err := s.store.OrgIDForDomain(r.Context(), domain); err == nil && orgID != "" {
			if role, _ := s.store.OrgRole(r.Context(), orgID, email); role == "" {
				if err := s.store.AddOrgMember(r.Context(), orgID, email, "member"); err == nil {
					s.log.Info("user auto-joined org by domain", "email", email, "org", orgID, "domain", domain)
				}
			}
		}
	}

	token, err := s.store.CreateSession(r.Context(), user.ID, sessionTTL, hashToken)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		MaxAge: int(sessionTTL / time.Second), HttpOnly: true,
		Secure: s.secureCookies(), SameSite: http.SameSiteLaxMode,
	})
	s.log.Info("user signed in", "email", user.Email, "admin", user.Admin)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		s.store.DeleteSession(r.Context(), hashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

type googleUserinfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

// googleIdentity exchanges the authorization code and fetches the user's
// identity from Google's userinfo endpoint (over TLS, so no local JWT
// verification is needed).
func (s *Server) googleIdentity(ctx context.Context, code string) (*googleUserinfo, error) {
	form := url.Values{
		"code":          {code},
		"client_id":     {s.cfg.Google.ClientID},
		"client_secret": {s.cfg.Google.ClientSecret},
		"redirect_uri":  {s.redirectURI()},
		"grant_type":    {"authorization_code"},
	}
	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleTokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange returned %s", resp.Status)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, err
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("token exchange returned no access token")
	}

	ureq, err := http.NewRequestWithContext(ctx, http.MethodGet, googleUserinfoURL, nil)
	if err != nil {
		return nil, err
	}
	ureq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	uresp, err := client.Do(ureq)
	if err != nil {
		return nil, err
	}
	defer uresp.Body.Close()
	if uresp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo returned %s", uresp.Status)
	}
	var info googleUserinfo
	if err := json.NewDecoder(uresp.Body).Decode(&info); err != nil {
		return nil, err
	}
	if info.Sub == "" || info.Email == "" {
		return nil, fmt.Errorf("userinfo missing sub or email")
	}
	return &info, nil
}

// sessionUser resolves the request's session cookie, if any.
func (s *Server) sessionUser(r *http.Request) (model.User, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return model.User{}, false
	}
	u, ok, err := s.store.SessionUser(r.Context(), hashToken(c.Value))
	if err != nil || !ok {
		return model.User{}, false
	}
	return u, true
}

// readScope decides what a read request may see.
//
//   - auth disabled           -> everything (lab mode)
//   - master token bearer     -> everything
//   - org enrollment token    -> that org only
//   - session (admin)         -> everything
//   - session (member)        -> the user's orgs
//
// The optional ?org= query parameter narrows the scope further; requesting an
// org outside the allowed set is an error. A nil return scope means "all
// orgs".
func (s *Server) readScope(r *http.Request) (orgIDs []string, err error) {
	requested := r.URL.Query().Get("org")
	narrow := func(allowed []string) ([]string, error) {
		if requested == "" {
			return allowed, nil
		}
		if allowed == nil {
			return []string{requested}, nil
		}
		for _, id := range allowed {
			if id == requested {
				return []string{requested}, nil
			}
		}
		return nil, fmt.Errorf("not a member of org %q", requested)
	}

	if !s.AuthEnabled() {
		return narrow(nil)
	}
	if tok := bearer(r); tok != "" {
		if s.masterAuthorized(r) {
			return narrow(nil)
		}
		orgID, err := s.store.OrgForTokenHash(r.Context(), hashToken(tok))
		if err != nil {
			return nil, err
		}
		if orgID != "" {
			return narrow([]string{orgID})
		}
		return nil, errUnauthorized
	}
	if user, ok := s.sessionUser(r); ok {
		if user.Admin {
			return narrow(nil)
		}
		orgs, err := s.store.UserOrgs(r.Context(), user.Email)
		if err != nil {
			return nil, err
		}
		if len(orgs) == 0 {
			return nil, fmt.Errorf("your account (%s) is not a member of any org yet — ask an admin for an invite", user.Email)
		}
		allowed := make([]string, len(orgs))
		for i, o := range orgs {
			allowed[i] = o.ID
		}
		return narrow(allowed)
	}
	return nil, errUnauthorized
}

var errUnauthorized = fmt.Errorf("unauthorized")

// requireReadScope wraps readScope with HTTP error handling; ok=false means a
// response was already written.
func (s *Server) requireReadScope(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	scope, err := s.readScope(r)
	if err == errUnauthorized {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return nil, false
	}
	return scope, true
}

// adminAuthorized allows the master token or an instance-admin session.
func (s *Server) adminAuthorized(r *http.Request) bool {
	if s.masterAuthorized(r) {
		return true
	}
	user, ok := s.sessionUser(r)
	return ok && user.Admin
}

// orgAdminAuthorized allows instance admins plus users holding the "admin"
// role in the given org — the self-service management boundary for tenants.
func (s *Server) orgAdminAuthorized(r *http.Request, orgID string) bool {
	if s.adminAuthorized(r) {
		return true
	}
	user, ok := s.sessionUser(r)
	if !ok {
		return false
	}
	role, err := s.store.OrgRole(r.Context(), orgID, user.Email)
	return err == nil && role == "admin"
}
