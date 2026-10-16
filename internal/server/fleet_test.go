package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

func TestRolloutRoundTrip(t *testing.T) {
	_, st := newTestServer(t)
	ctx := context.Background()
	// default: empty
	r0, err := st.GetRollout(ctx)
	if err != nil || r0.StableVersion != "" || len(r0.CanaryIDs) != 0 {
		t.Fatalf("default rollout = %+v err=%v, want empty", r0, err)
	}
	want := model.AgentRollout{StableVersion: "v0.99.0", CanaryVersion: "v1.0.0", CanaryIDs: []string{"a", "b"}}
	if err := st.SetRollout(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetRollout(ctx)
	if err != nil || got.StableVersion != "v0.99.0" || got.CanaryVersion != "v1.0.0" || len(got.CanaryIDs) != 2 {
		t.Fatalf("round-trip = %+v err=%v", got, err)
	}
}

func TestDesiredVersionFor(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	srv.cfg.AgentDesiredVersion = "v0.98.0" // the env/flag pin fallback

	// no rollout → fall back to the configured pin
	if v := srv.desiredVersionFor(ctx, "host1"); v != "v0.98.0" {
		t.Errorf("no rollout: got %q, want v0.98.0 (pin)", v)
	}

	// stable only → everyone gets stable
	st.SetRollout(ctx, model.AgentRollout{StableVersion: "v0.99.0"})
	srv.rolloutAt = time.Time{} // invalidate cache
	if v := srv.desiredVersionFor(ctx, "host1"); v != "v0.99.0" {
		t.Errorf("stable-only: got %q, want v0.99.0", v)
	}

	// stable + canary cohort → canary host gets canary, others stable
	st.SetRollout(ctx, model.AgentRollout{StableVersion: "v0.99.0", CanaryVersion: "v1.0.0", CanaryIDs: []string{"canaryhost"}})
	srv.rolloutAt = time.Time{}
	if v := srv.desiredVersionFor(ctx, "canaryhost"); v != "v1.0.0" {
		t.Errorf("canary host: got %q, want v1.0.0", v)
	}
	if v := srv.desiredVersionFor(ctx, "host1"); v != "v0.99.0" {
		t.Errorf("non-canary host: got %q, want v0.99.0", v)
	}
}

func TestFleetHandlerAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	// no token → unauthorized
	w := httptest.NewRecorder()
	srv.handleFleet(w, httptest.NewRequest("GET", "/api/v1/fleet", nil))
	if w.Code == 200 {
		t.Errorf("unauthenticated fleet must not be 200, got %d", w.Code)
	}
	// master token → ok, valid shape
	w = httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/fleet", nil)
	r.Header.Set("Authorization", "Bearer master-secret")
	srv.handleFleet(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "\"total\"") {
		t.Fatalf("admin fleet: %d %s", w.Code, w.Body.String())
	}
}

func TestRolloutHandlerSetGet(t *testing.T) {
	srv, _ := newTestServer(t)
	body := `{"stable_version":"v0.99.0","canary_version":"v1.0.0","canary_ids":["h1"]}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/fleet/rollout", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer master-secret")
	r.Header.Set("Content-Type", "application/json")
	srv.handleRolloutSet(w, r)
	if w.Code != 200 {
		t.Fatalf("set rollout: %d %s", w.Code, w.Body.String())
	}
	// GET reflects it
	w = httptest.NewRecorder()
	gr := httptest.NewRequest("GET", "/api/v1/fleet/rollout", nil)
	gr.Header.Set("Authorization", "Bearer master-secret")
	srv.handleRolloutGet(w, gr)
	if !strings.Contains(w.Body.String(), "v1.0.0") {
		t.Errorf("get rollout missing canary: %s", w.Body.String())
	}
	// resolver reflects it immediately (handler invalidated the cache)
	if v := srv.desiredVersionFor(context.Background(), "h1"); v != "v1.0.0" {
		t.Errorf("resolver after set: got %q, want v1.0.0", v)
	}
}
