package server

import (
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestDeployRegressionReasons(t *testing.T) {
	sh := func(er, p95 float64) model.ServiceHealth {
		return model.ServiceHealth{ErrorRate: er, P95Ms: p95}
	}
	cases := []struct {
		name           string
		before, after  model.ServiceHealth
		wantRegression bool
	}{
		{"error rate jump", sh(0.01, 100), sh(0.20, 120), true},      // 1%→20%
		{"p95 blowout", sh(0.01, 200), sh(0.01, 800), true},          // 200→800ms (>1.5x, >floor)
		{"steady", sh(0.02, 150), sh(0.03, 180), false},              // small drift, no regression
		{"small p95 rise under floor", sh(0, 40), sh(0, 120), false}, // 3x but under 150ms floor
		{"error rate recovered", sh(0.30, 100), sh(0.02, 100), false},
	}
	for _, c := range cases {
		got := len(deployRegressionReasons(c.before, c.after)) > 0
		if got != c.wantRegression {
			t.Errorf("%s: regression=%v, want %v (reasons=%v)", c.name, got, c.wantRegression, deployRegressionReasons(c.before, c.after))
		}
	}
}
