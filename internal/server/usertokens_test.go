package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/soc-foundry/varro/internal/store"
)

// newTestServer spins a server backed by a temp SQLite store with auth enabled.
func newTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	srv := New(Config{
		Token:  "master-secret",
		Google: GoogleConfig{ClientID: "test-client"}, // makes AuthEnabled() true
	}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return srv, st
}

func bearerReq(tok string) *http.Request {
	r, _ := http.NewRequest("GET", "/api/v1/endpoints", nil)
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	return r
}

func TestPersonalAPITokenScopeAndRevoke(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	// First user is an instance admin; second is a plain member of one org.
	admin, err := st.UpsertGoogleUser(ctx, "sub-admin", "admin@x.com", "Admin", true)
	if err != nil {
		t.Fatal(err)
	}
	member, err := st.UpsertGoogleUser(ctx, "sub-mem", "member@x.com", "Member", false)
	if err != nil {
		t.Fatal(err)
	}
	org, err := st.CreateOrg(ctx, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddOrgMember(ctx, org.ID, member.Email, "member"); err != nil {
		t.Fatal(err)
	}

	adminTok, _, err := st.CreateUserToken(ctx, admin.ID, admin.Email, "cli", hashToken)
	if err != nil {
		t.Fatal(err)
	}
	memTok, memTokID, err := st.CreateUserToken(ctx, member.ID, member.Email, "cli", hashToken)
	if err != nil {
		t.Fatal(err)
	}

	// Admin personal token -> full scope (nil) + admin authorization.
	scope, err := srv.readScope(bearerReq(adminTok))
	if err != nil {
		t.Fatalf("admin readScope: %v", err)
	}
	if scope != nil {
		t.Fatalf("admin token should have all-org scope (nil), got %v", scope)
	}
	if !srv.adminAuthorized(bearerReq(adminTok)) {
		t.Fatal("admin token should be adminAuthorized")
	}

	// Member personal token -> scoped to exactly their org, NOT admin.
	scope, err = srv.readScope(bearerReq(memTok))
	if err != nil {
		t.Fatalf("member readScope: %v", err)
	}
	if len(scope) != 1 || scope[0] != org.ID {
		t.Fatalf("member token scope = %v, want [%s]", scope, org.ID)
	}
	if srv.adminAuthorized(bearerReq(memTok)) {
		t.Fatal("member token must NOT be adminAuthorized")
	}
	if !srv.orgAdminAuthorized(bearerReq(adminTok), org.ID) {
		t.Fatal("admin token should pass orgAdminAuthorized")
	}
	if srv.orgAdminAuthorized(bearerReq(memTok), org.ID) {
		t.Fatal("plain member token must NOT pass orgAdminAuthorized")
	}

	// A bogus bearer is unauthorized.
	if _, err := srv.readScope(bearerReq("not-a-real-token")); err != errUnauthorized {
		t.Fatalf("bogus token err = %v, want errUnauthorized", err)
	}

	// Revoke the member token -> it stops resolving; admin token still works.
	removed, err := st.DeleteUserToken(ctx, member.ID, memTokID)
	if err != nil || !removed {
		t.Fatalf("revoke: removed=%v err=%v", removed, err)
	}
	if _, err := srv.readScope(bearerReq(memTok)); err != errUnauthorized {
		t.Fatalf("revoked token err = %v, want errUnauthorized", err)
	}
	if _, err := srv.readScope(bearerReq(adminTok)); err != nil {
		t.Fatalf("admin token should still work after member revoke: %v", err)
	}

	// Revoke is owner-scoped: member cannot revoke the admin's token.
	removed, err = st.DeleteUserToken(ctx, member.ID, memTokID)
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("second revoke of same token should report not-removed")
	}
}

func TestPersonalTokenAdminFollowsLiveStatus(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	admin, err := st.UpsertGoogleUser(ctx, "sub-a", "a@x.com", "A", true)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := st.CreateUserToken(ctx, admin.ID, admin.Email, "cli", hashToken)
	if err != nil {
		t.Fatal(err)
	}
	if !srv.adminAuthorized(bearerReq(tok)) {
		t.Fatal("token owner is admin -> should be adminAuthorized")
	}
	// Demote the user: the SAME token must immediately lose admin rights, since
	// scope is resolved live from the user, not baked into the token.
	if _, err := st.SetUserAdmin(ctx, admin.Email, false); err != nil {
		t.Fatalf("SetUserAdmin: %v", err)
	}
	if srv.adminAuthorized(bearerReq(tok)) {
		t.Fatal("after demotion the token must NOT be adminAuthorized")
	}
}
