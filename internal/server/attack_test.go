package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestExtractTechniques(t *testing.T) {
	got := extractTechniques("T1059.004 and T1071, plus noise T99 and T1021")
	want := []string{"T1059.004", "T1071", "T1021"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
	if parentTechnique("T1059.004") != "T1059" || parentTechnique("T1071") != "T1071" {
		t.Errorf("parentTechnique wrong")
	}
}

func TestAttackCoverageHandler(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	// Baseline: all 5 built-ins enabled by default → T1059, T1496, T1046 covered.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/attack?org=default", nil)
	r.Header.Set("Authorization", "Bearer master-secret")
	srv.handleAttackCoverage(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var cov model.AttackCoverage
	if err := json.Unmarshal(w.Body.Bytes(), &cov); err != nil {
		t.Fatal(err)
	}
	find := func(id string) *model.AttackTechnique {
		for i := range cov.Tactics {
			for j := range cov.Tactics[i].Techniques {
				if cov.Tactics[i].Techniques[j].ID == id {
					return &cov.Tactics[i].Techniques[j]
				}
			}
		}
		return nil
	}
	if te := find("T1059"); te == nil || !te.Covered {
		t.Errorf("T1059 should be covered by built-ins: %+v", te)
	}
	if te := find("T1486"); te == nil || te.Covered {
		t.Errorf("T1486 (no rule) should be a gap: %+v", te)
	}
	baselineCovered := cov.CoveredTechniques

	// Disable the two T1059 built-ins → T1059 no longer covered (exec_storm also T1059,
	// so disable all three), coverage drops.
	for _, name := range []string{"reverse_shell", "shell_listener", "exec_storm"} {
		st.SetDetectionSetting(ctx, "default", model.DetectionSetting{RuleName: name, Enabled: false})
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/api/v1/attack?org=default", nil)
	r.Header.Set("Authorization", "Bearer master-secret")
	srv.handleAttackCoverage(w, r)
	json.Unmarshal(w.Body.Bytes(), &cov)
	if te := find("T1059"); te == nil || te.Covered {
		t.Errorf("T1059 should be uncovered after disabling its built-ins: %+v", te)
	}
	if cov.CoveredTechniques >= baselineCovered {
		t.Errorf("coverage should drop after disabling: was %d now %d", baselineCovered, cov.CoveredTechniques)
	}
}
