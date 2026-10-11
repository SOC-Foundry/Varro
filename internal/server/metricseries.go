package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// metricExtractors maps an API metric name to the HistoryPoint field it reads.
// Keyed by the same JSON names HistoryPoint exposes, so the UI and API agree.
var metricExtractors = map[string]func(model.HistoryPoint) float64{
	"cpu_percent":  func(p model.HistoryPoint) float64 { return p.CPUPercent },
	"mem_percent":  func(p model.HistoryPoint) float64 { return p.MemPercent },
	"disk_percent": func(p model.HistoryPoint) float64 { return p.DiskPct },
	"rx_rate_bps":  func(p model.HistoryPoint) float64 { return p.RxRate },
	"tx_rate_bps":  func(p model.HistoryPoint) float64 { return p.TxRate },
	"io_read_bps":  func(p model.HistoryPoint) float64 { return p.IoReadBps },
	"io_write_bps": func(p model.HistoryPoint) float64 { return p.IoWriteBps },
	"max_temp_c":   func(p model.HistoryPoint) float64 { return p.MaxTemp },
	"mem_used":     func(p model.HistoryPoint) float64 { return float64(p.MemUsed) },
}

// handleMetricSeries returns one metric's time series for several endpoints at
// once — the data behind the metric-explorer view. Read-scoped; only endpoints
// in scope are returned.
func (s *Server) handleMetricSeries(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	metric := q.Get("metric")
	extract := metricExtractors[metric]
	if extract == nil {
		http.Error(w, "unknown metric", http.StatusBadRequest)
		return
	}
	minutes := 60
	if v, err := strconv.Atoi(q.Get("minutes")); err == nil && v > 0 && v <= 20160 {
		minutes = v
	}
	// ~300 points across the window, floor 10s.
	step := minutes * 60 / 300
	if step < 10 {
		step = 10
	}
	to := time.Now()
	from := to.Add(-time.Duration(minutes) * time.Minute)

	// Restrict requested endpoints to those in scope.
	eps, err := s.store.Endpoints(r.Context(), scope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	host := map[string]string{}
	for _, ep := range eps {
		host[ep.ID] = ep.Hostname
	}
	want := strings.Split(q.Get("endpoints"), ",")

	type series struct {
		EndpointID string       `json:"endpoint_id"`
		Hostname   string       `json:"hostname"`
		Points     [][2]float64 `json:"points"` // [ts, value]
	}
	out := []series{}
	for _, id := range want {
		id = strings.TrimSpace(id)
		if id == "" || host[id] == "" {
			continue // unknown or out of scope
		}
		pts, err := s.store.History(r.Context(), id, from, to, step)
		if err != nil {
			continue
		}
		ser := series{EndpointID: id, Hostname: host[id], Points: [][2]float64{}}
		for _, p := range pts {
			ser.Points = append(ser.Points, [2]float64{float64(p.Timestamp), extract(p)})
		}
		out = append(out, ser)
	}
	writeJSON(w, map[string]any{"metric": metric, "minutes": minutes, "step": step, "series": out})
}
