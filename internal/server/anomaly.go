package server

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

const (
	anomalyZ              = 3.0           // deviation (in stddevs) to flag
	anomalyBaselineWindow = 6 * time.Hour // trailing window for the baseline
	anomalyMinPoints      = 30            // need this many baseline buckets to judge
	anomalyStdFloor       = 1.0           // min stddev (pct points) — avoids hypersensitivity on flat metrics
)

// meanStd returns the mean and population standard deviation of vals.
func meanStd(vals []float64) (mean, std float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean = sum / float64(len(vals))
	var ss float64
	for _, v := range vals {
		d := v - mean
		ss += d * d
	}
	return mean, math.Sqrt(ss / float64(len(vals)))
}

// detectAnomaly reports whether current is anomalously high versus a baseline:
// at least anomalyMinPoints of history, z = (current-mean)/stddev >= anomalyZ, and
// current is above a per-metric relevance floor (so an idle host jittering doesn't
// alert). Returns the z-score and baseline mean for the message.
func detectAnomaly(baseline []float64, current, floor float64) (z, mean float64, anomalous bool) {
	if len(baseline) < anomalyMinPoints {
		return 0, 0, false
	}
	mean, std := meanStd(baseline)
	if std < anomalyStdFloor {
		std = anomalyStdFloor
	}
	z = (current - mean) / std
	return z, mean, z >= anomalyZ && current >= floor
}

// anomalyLoop scans each online endpoint's recent metric history on the leader and
// raises anomalies where the latest value deviates sharply from the host's own
// baseline. Runs every 5 minutes.
func (s *Server) anomalyLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.isLeader() {
				s.checkAnomalies(ctx)
			}
		}
	}
}

func (s *Server) checkAnomalies(ctx context.Context) {
	eps, err := s.store.Endpoints(ctx, nil)
	if err != nil {
		s.log.Error("anomaly: list endpoints", "error", err)
		return
	}
	// Resource percentages are naturally bounded and have meaningful floors, so
	// they alert on genuine pressure that's unusual for THAT host (low noise).
	metrics := []struct {
		name  string
		get   func(model.HistoryPoint) float64
		floor float64
	}{
		{"CPU", func(p model.HistoryPoint) float64 { return p.CPUPercent }, 60},
		{"memory", func(p model.HistoryPoint) float64 { return p.MemPercent }, 70},
		{"disk", func(p model.HistoryPoint) float64 { return p.DiskPct }, 85},
	}
	now := time.Now()
	for _, ep := range eps {
		if !ep.Online {
			continue
		}
		hist, err := s.store.History(ctx, ep.ID, now.Add(-anomalyBaselineWindow), now, 60)
		if err != nil || len(hist) < anomalyMinPoints+1 {
			continue
		}
		cur := hist[len(hist)-1]
		base := hist[:len(hist)-1]
		for _, m := range metrics {
			vals := make([]float64, len(base))
			for i, p := range base {
				vals[i] = m.get(p)
			}
			z, mean, anom := detectAnomaly(vals, m.get(cur), m.floor)
			if !anom || !s.driftShouldAlert("anomaly|"+ep.ID+"|"+m.name, time.Hour) {
				continue
			}
			msg := fmt.Sprintf("metric anomaly: %s %s %.0f%% is %.1fσ above its ~%dh baseline (mean %.0f%%)",
				ep.Hostname, m.name, m.get(cur), z, int(anomalyBaselineWindow/time.Hour), mean)
			if err := s.store.InsertServerEvent(ctx, ep.OrgID, ep.ID, model.EventMetricAnomaly, msg); err != nil {
				continue
			}
			s.log.Info("metric anomaly", "endpoint", ep.Hostname, "metric", m.name, "value", m.get(cur), "z", z)
			s.notifyEvents(ep.OrgID, ep.Hostname, []model.Event{{Type: model.EventMetricAnomaly, Message: msg}})
			s.siemForward(ep.OrgID, ep.Hostname, model.EventMetricAnomaly, "MEDIUM", "", msg)
		}
	}
}
