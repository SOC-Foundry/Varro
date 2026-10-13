package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

const (
	probeTimeout    = 10 * time.Second
	probeTick       = 10 * time.Second
	minInterval     = 10
	maxInterval     = 3600
	maxChecksPerOrg = 50
)

// handleSyntheticList returns the caller's in-scope checks with current status.
func (s *Server) handleSyntheticList(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	st, err := s.store.SyntheticStatuses(r.Context(), scope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if st == nil {
		st = []model.SyntheticStatus{}
	}
	writeJSON(w, map[string]any{"checks": st})
}

// handleSyntheticCreate adds a check. Requires org-admin on the target org.
func (s *Server) handleSyntheticCreate(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	var req struct {
		OrgID      string `json:"org_id"`
		Name       string `json:"name"`
		Type       string `json:"type"`
		Target     string `json:"target"`
		IntervalS  int    `json:"interval_seconds"`
		ExpectCode int    `json:"expect_status"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	orgID := req.OrgID
	if orgID == "" && len(scope) > 0 {
		orgID = scope[0]
	}
	if orgID == "" {
		http.Error(w, "org_id required", http.StatusBadRequest)
		return
	}
	if !s.orgAdminAuthorized(r, orgID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	check, err := validateCheck(req.Name, req.Type, req.Target, req.IntervalS, req.ExpectCode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	check.OrgID = orgID
	check.Enabled = true

	existing, err := s.store.SyntheticChecks(r.Context(), []string{orgID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(existing) >= maxChecksPerOrg {
		http.Error(w, fmt.Sprintf("too many checks (max %d per org)", maxChecksPerOrg), http.StatusBadRequest)
		return
	}
	created, err := s.store.CreateSyntheticCheck(r.Context(), check)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.Info("synthetic check created", "org", orgID, "name", created.Name, "type", created.Type, "target", created.Target)
	s.audit(r, "synthetic.create", orgID, created.Type+" "+created.Name)
	writeJSON(w, created)
}

// handleSyntheticDelete removes a check within the caller's scope.
func (s *Server) handleSyntheticDelete(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	// Resolve the check's org so we can enforce org-admin (not just read scope).
	checks, err := s.store.SyntheticChecks(r.Context(), scope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var orgID string
	for _, c := range checks {
		if c.ID == id {
			orgID = c.OrgID
			break
		}
	}
	if orgID == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !s.orgAdminAuthorized(r, orgID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	removed, err := s.store.DeleteSyntheticCheck(r.Context(), scope, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.audit(r, "synthetic.delete", orgID, id)
	writeJSON(w, map[string]bool{"removed": true})
}

// handleSyntheticResults returns a check's recent probe results for charting.
func (s *Server) handleSyntheticResults(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	minutes, _ := strconv.Atoi(r.URL.Query().Get("minutes"))
	if minutes <= 0 {
		minutes = 6 * 60
	}
	if minutes > 7*24*60 {
		minutes = 7 * 24 * 60
	}
	since := time.Now().Add(-time.Duration(minutes) * time.Minute).Unix()
	results, err := s.store.ProbeResults(r.Context(), scope, id, since, 2000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if results == nil {
		results = []model.ProbeResult{}
	}
	writeJSON(w, map[string]any{"results": results})
}

// validateCheck normalizes and validates a check request.
func validateCheck(name, typ, target string, intervalS, expectCode int) (model.SyntheticCheck, error) {
	c := model.SyntheticCheck{}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return c, fmt.Errorf("name is required (max 100 chars)")
	}
	target = strings.TrimSpace(target)
	switch typ {
	case model.ProbeHTTP, "":
		typ = model.ProbeHTTP
		u, err := url.Parse(target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return c, fmt.Errorf("http target must be an http(s) URL")
		}
	case model.ProbeTCP:
		host, port, err := net.SplitHostPort(target)
		if err != nil || host == "" {
			return c, fmt.Errorf("tcp target must be host:port")
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return c, fmt.Errorf("tcp target port must be 1-65535")
		}
	default:
		return c, fmt.Errorf("type must be http or tcp")
	}
	if intervalS == 0 {
		intervalS = 60
	}
	if intervalS < minInterval {
		intervalS = minInterval
	}
	if intervalS > maxInterval {
		intervalS = maxInterval
	}
	if expectCode != 0 && (expectCode < 100 || expectCode > 599) {
		return c, fmt.Errorf("expect_status must be 100-599 (or 0 for any 2xx/3xx)")
	}
	c.Name, c.Type, c.Target, c.IntervalS, c.ExpectCode = name, typ, target, intervalS, expectCode
	return c, nil
}

// proberLoop runs on the leader, probing each enabled check on its interval.
func (s *Server) proberLoop(ctx context.Context) {
	t := time.NewTicker(probeTick)
	defer t.Stop()
	last := map[string]time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !s.isLeader() {
				continue
			}
			checks, err := s.store.EnabledSyntheticChecks(ctx)
			if err != nil {
				s.log.Error("prober: list checks", "error", err)
				continue
			}
			now := time.Now()
			live := map[string]bool{}
			for _, c := range checks {
				live[c.ID] = true
				iv := time.Duration(c.IntervalS) * time.Second
				if iv < minInterval*time.Second {
					iv = minInterval * time.Second
				}
				if now.Sub(last[c.ID]) < iv {
					continue
				}
				last[c.ID] = now
				go s.runProbe(ctx, c)
			}
			// Drop bookkeeping for checks that no longer exist.
			for id := range last {
				if !live[id] {
					delete(last, id)
				}
			}
		}
	}
}

// runProbe executes one probe, records the result, and reconciles its alert.
func (s *Server) runProbe(ctx context.Context, c model.SyntheticCheck) {
	infra, _ := s.store.OrgIsInfrastructure(ctx, c.OrgID)
	res := s.probe(ctx, c, infra)
	res.CheckID = c.ID
	res.TS = time.Now().Unix()
	if err := s.store.InsertProbeResult(ctx, res, c.OrgID); err != nil {
		s.log.Error("prober: insert result", "check", c.Name, "error", err)
	}
	ep := model.EndpointSummary{ID: "probe/" + c.OrgID + "/" + c.ID, Hostname: c.Name, OrgID: c.OrgID}
	var msg string
	if res.OK {
		msg = fmt.Sprintf("probe %s (%s) recovered (%.0fms)", c.Name, c.Target, res.LatencyMs)
	} else {
		msg = fmt.Sprintf("probe %s (%s) is down: %s", c.Name, c.Target, res.Error)
	}
	s.setAlertState(ctx, "synthetic-down", ep, !res.OK, res.LatencyMs, msg)
}

// probe performs a single HTTP or TCP check. The dialer's Control hook runs
// after DNS resolution on every connect attempt (including redirects), so it
// blocks SSRF to loopback/link-local (incl. cloud metadata) for all orgs and to
// private ranges for non-infrastructure orgs — defeating DNS rebinding.
func (s *Server) probe(ctx context.Context, c model.SyntheticCheck, infra bool) model.ProbeResult {
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: probeTimeout, Control: probeDialControl(infra)}
	start := time.Now()

	switch c.Type {
	case model.ProbeTCP:
		conn, err := dialer.DialContext(pctx, "tcp", c.Target)
		lat := msSince(start)
		if err != nil {
			return model.ProbeResult{OK: false, LatencyMs: lat, Error: briefErr(err)}
		}
		conn.Close()
		return model.ProbeResult{OK: true, LatencyMs: lat}

	default: // http
		req, err := http.NewRequestWithContext(pctx, http.MethodGet, c.Target, nil)
		if err != nil {
			return model.ProbeResult{OK: false, Error: briefErr(err)}
		}
		req.Header.Set("User-Agent", "varro-synthetic/1.0")
		tr := &http.Transport{
			DialContext:         dialer.DialContext,
			TLSHandshakeTimeout: probeTimeout,
			DisableKeepAlives:   true,
			ForceAttemptHTTP2:   true,
		}
		client := &http.Client{Transport: tr, Timeout: probeTimeout}
		resp, err := client.Do(req)
		lat := msSince(start)
		if err != nil {
			return model.ProbeResult{OK: false, LatencyMs: lat, Error: briefErr(err)}
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close()
		ok := resp.StatusCode >= 200 && resp.StatusCode < 400
		if c.ExpectCode != 0 {
			ok = resp.StatusCode == c.ExpectCode
		}
		out := model.ProbeResult{OK: ok, LatencyMs: lat, Code: resp.StatusCode}
		if !ok {
			out.Error = fmt.Sprintf("unexpected status %d", resp.StatusCode)
		}
		return out
	}
}

// probeDialControl returns a net.Dialer Control hook that vets each resolved IP
// before the socket connects.
func probeDialControl(infra bool) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("could not resolve target address")
		}
		return allowedProbeIP(infra, ip)
	}
}

// allowedProbeIP enforces the SSRF policy. Link-local (169.254.0.0/16 incl. the
// cloud metadata endpoint, fe80::/10), multicast, and the unspecified address
// are blocked for everyone. Loopback and private ranges are allowed only for an
// Infrastructure org (operator-controlled, for monitoring internal services).
func allowedProbeIP(infra bool, ip net.IP) error {
	switch {
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast():
		return fmt.Errorf("link-local address not allowed")
	case ip.IsUnspecified() || ip.IsMulticast():
		return fmt.Errorf("address not allowed")
	case ip.IsLoopback():
		if infra {
			return nil
		}
		return fmt.Errorf("loopback address not allowed")
	case ip.IsPrivate():
		if infra {
			return nil
		}
		return fmt.Errorf("private address not allowed for this org")
	}
	return nil
}

func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000.0
}

// briefErr shortens an error for storage/display (never carries secrets, but we
// cap length and strip newlines).
func briefErr(err error) string {
	msg := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}
