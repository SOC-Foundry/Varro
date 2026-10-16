package server

import (
	"math"
	"testing"
)

func TestMeanStd(t *testing.T) {
	mean, std := meanStd([]float64{2, 4, 4, 4, 5, 5, 7, 9})
	if mean != 5 {
		t.Errorf("mean = %v, want 5", mean)
	}
	if math.Abs(std-2) > 1e-9 {
		t.Errorf("std = %v, want 2", std)
	}
	if m, s := meanStd(nil); m != 0 || s != 0 {
		t.Errorf("empty = %v/%v, want 0/0", m, s)
	}
}

func baselineOf(v float64, n int) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func TestDetectAnomaly(t *testing.T) {
	// Flat ~20% baseline (stddev floored to 1), current 80% → huge z, above floor 60 → anomaly.
	base := baselineOf(20, 60)
	z, mean, anom := detectAnomaly(base, 80, 60)
	if !anom {
		t.Errorf("80%% vs flat 20%% baseline should be anomalous (z=%.1f)", z)
	}
	if mean != 20 {
		t.Errorf("mean = %v, want 20", mean)
	}

	// Same spike shape but below the relevance floor → not flagged (idle host jitter).
	if _, _, a := detectAnomaly(baselineOf(2, 60), 40, 60); a {
		t.Error("40%% is a big z but below the 60%% floor — must not alert")
	}

	// Not enough history → never anomalous.
	if _, _, a := detectAnomaly(baselineOf(20, 10), 99, 60); a {
		t.Error("with <min points, must not alert")
	}

	// High but within normal variation for a busy host → not anomalous.
	busy := []float64{}
	for i := 0; i < 60; i++ {
		busy = append(busy, 70+float64(i%20)) // 70..89, mean ~79, std ~6
	}
	if _, _, a := detectAnomaly(busy, 85, 60); a {
		t.Error("85%% on a host that regularly runs 70-89%% should not be anomalous")
	}
	// A true spike on that busy host does fire.
	if _, _, a := detectAnomaly(busy, 99, 60); !a {
		t.Error("99%% on a 70-89%% host should be anomalous")
	}
}
