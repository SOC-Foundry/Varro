package server

import (
	"math"
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestSLOEvaluate(t *testing.T) {
	slo := model.SLO{Service: "api", Target: 0.99, WindowMinutes: 60} // 1% error budget

	// No traffic → no-data.
	if st := sloEvaluate(slo, nil); st.Status != "no-data" {
		t.Errorf("nil health: status %q, want no-data", st.Status)
	}
	if st := sloEvaluate(slo, &model.ServiceHealth{Requests: 0}); st.Status != "no-data" {
		t.Errorf("0 requests: status %q, want no-data", st.Status)
	}

	// 0.2% errors vs 1% budget → 20% consumed → ok.
	st := sloEvaluate(slo, &model.ServiceHealth{Requests: 1000, Errors: 2, ErrorRate: 0.002})
	if st.Status != "ok" || math.Abs(st.BudgetConsumed-0.2) > 1e-9 {
		t.Errorf("ok case: status=%q consumed=%.3f, want ok/0.2", st.Status, st.BudgetConsumed)
	}

	// 0.8% errors → 80% consumed → warning.
	st = sloEvaluate(slo, &model.ServiceHealth{Requests: 1000, Errors: 8, ErrorRate: 0.008})
	if st.Status != "warning" {
		t.Errorf("warning case: status=%q consumed=%.3f, want warning", st.Status, st.BudgetConsumed)
	}

	// 1.5% errors > 1% budget → breached.
	st = sloEvaluate(slo, &model.ServiceHealth{Requests: 1000, Errors: 15, ErrorRate: 0.015})
	if st.Status != "breached" || st.BudgetConsumed < 1 {
		t.Errorf("breached case: status=%q consumed=%.3f, want breached/≥1", st.Status, st.BudgetConsumed)
	}
}
