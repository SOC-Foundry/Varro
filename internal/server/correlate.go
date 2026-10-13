package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// Cross-endpoint correlation: a single known-bad indicator (IP, domain, or
// malware hash) seen on many endpoints at once is a stronger, campaign-level
// signal than any one host's match. The correlator tracks which endpoints hit
// each indicator within a rolling window and fires once it crosses a threshold.
//
// State is per-collector; with the current single public collector that sees
// all ingest, this catches fleet-wide campaigns. (Shared-state correlation
// across multiple serving collectors would be a follow-up.)
const (
	corrWindow    = 30 * time.Minute
	corrThreshold = 3             // distinct endpoints hitting one indicator
	corrReFire    = 1 * time.Hour // don't re-raise the same indicator this often
)

type correlator struct {
	mu    sync.Mutex
	hits  map[string]map[string]time.Time // indicator -> endpoint -> last seen
	fired map[string]time.Time            // indicator -> last correlated fire
}

func newCorrelator() *correlator {
	return &correlator{hits: map[string]map[string]time.Time{}, fired: map[string]time.Time{}}
}

// observe records that `endpoint` hit `indicator` and returns the number of
// distinct endpoints that have hit it within the window, plus whether this
// crossing should raise a (rate-limited) correlated detection.
func (c *correlator) observe(indicator, endpoint string) (distinct int, fire bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()

	eps := c.hits[indicator]
	if eps == nil {
		eps = map[string]time.Time{}
		c.hits[indicator] = eps
	}
	eps[endpoint] = now
	for ep, t := range eps { // evict stale observations
		if now.Sub(t) > corrWindow {
			delete(eps, ep)
		}
	}
	distinct = len(eps)
	if distinct < corrThreshold {
		return distinct, false
	}
	if last, ok := c.fired[indicator]; ok && now.Sub(last) < corrReFire {
		return distinct, false
	}
	c.fired[indicator] = now
	return distinct, true
}

// raiseCoordinated emits a campaign-level detection when one indicator has hit
// many endpoints, and ships it to notifiers + SIEM.
func (s *Server) raiseCoordinated(ctx context.Context, orgID, host, agentID, indicator string, n int) {
	msg := fmt.Sprintf("[CRITICAL] coordinated_threat (ATT&CK T1071 Application Layer Protocol): known-bad %s observed on %d endpoints within %s — possible coordinated campaign",
		indicator, n, corrWindow)
	s.store.InsertServerEvent(ctx, orgID, agentID, model.EventDetection, msg)
	s.log.Warn("coordinated threat", "indicator", indicator, "endpoints", n)
	s.notifyEvents(orgID, host, []model.Event{{Type: model.EventDetection, Message: msg}})
	s.siemForward(orgID, host, "coordinated_threat", "CRITICAL", "T1071 Application Layer Protocol", msg)
}
