package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

const (
	osvBatchURL = "https://api.osv.dev/v1/querybatch"
	osvVulnURL  = "https://api.osv.dev/v1/vulns/"

	vulnCheckEvery   = 1 * time.Hour  // how often the loop looks for work
	vulnRescanEvery  = 24 * time.Hour // full rescan cadence (new CVEs publish daily)
	osvBatchMax      = 950            // querybatch limit is 1000
	detailFetchCap   = 60             // detail lookups per cycle
	vulnEventCap     = 15             // vuln_new events per endpoint per scan
)

// osvEcosystem maps an endpoint's package manager + platform to an OSV
// ecosystem. Empty means OSV has no coverage for it (Arch, Windows, macOS).
func osvEcosystem(manager, platform string) string {
	switch manager {
	case "dpkg":
		if strings.Contains(strings.ToLower(platform), "ubuntu") {
			return "Ubuntu"
		}
		return "Debian"
	case "rpm":
		p := strings.ToLower(platform)
		switch {
		case strings.Contains(p, "rocky"):
			return "Rocky Linux"
		case strings.Contains(p, "alma"):
			return "AlmaLinux"
		}
		return ""
	case "apk":
		return "Alpine"
	}
	return ""
}

// vulnScanLoop periodically scans endpoints whose inventory changed since
// their last scan, or whose scan is older than the rescan cadence.
func (s *Server) vulnScanLoop(ctx context.Context) {
	// First pass shortly after startup so fresh deployments get results fast.
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.scanAllEndpoints(ctx)
		// Drain the details queue in capped batches so fresh findings are
		// annotated promptly without hammering OSV in one burst.
		for i := 0; i < 20; i++ {
			if done := s.fetchVulnDetails(ctx); done {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
		timer.Reset(vulnCheckEvery)
	}
}

func (s *Server) scanAllEndpoints(ctx context.Context) {
	eps, err := s.store.Endpoints(ctx, nil)
	if err != nil {
		return
	}
	for _, ep := range eps {
		inv, invTS, err := s.store.Inventory(ctx, ep.ID)
		if err != nil || inv == nil {
			continue
		}
		scannedAt, scannedInv, err := s.store.VulnScanState(ctx, ep.ID)
		if err != nil {
			continue
		}
		fresh := invTS.Unix() > scannedInv
		stale := time.Since(time.Unix(scannedAt, 0)) > vulnRescanEvery
		if !fresh && !stale {
			continue
		}
		eco := osvEcosystem(inv.Manager, ep.Platform)
		if eco == "" {
			// Record the scan so unsupported platforms aren't retried hourly.
			s.store.ReplaceEndpointVulns(ctx, ep.ID, nil, invTS.Unix())
			continue
		}
		found, err := s.osvQuery(ctx, eco, inv.Packages)
		if err != nil {
			s.log.Error("vuln scan failed", "endpoint", ep.Hostname, "error", err)
			continue
		}
		newOnes, err := s.store.ReplaceEndpointVulns(ctx, ep.ID, found, invTS.Unix())
		if err != nil {
			s.log.Error("vuln store failed", "endpoint", ep.Hostname, "error", err)
			continue
		}
		s.log.Info("vulnerability scan complete", "endpoint", ep.Hostname,
			"ecosystem", eco, "packages", len(inv.Packages), "findings", len(found), "new", len(newOnes))
		for i, v := range newOnes {
			if i >= vulnEventCap {
				s.store.InsertServerEvent(ctx, ep.OrgID, ep.ID, model.EventVulnNew,
					fmt.Sprintf("...and %d more new vulnerability findings", len(newOnes)-vulnEventCap))
				break
			}
			s.store.InsertServerEvent(ctx, ep.OrgID, ep.ID, model.EventVulnNew,
				fmt.Sprintf("%s %s affected by %s", v.Package, v.Version, v.ID))
		}
	}
}

// osvQuery batch-matches packages against OSV.
func (s *Server) osvQuery(ctx context.Context, ecosystem string, pkgs []model.Package) ([]model.Vulnerability, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	var found []model.Vulnerability
	for start := 0; start < len(pkgs); start += osvBatchMax {
		end := start + osvBatchMax
		if end > len(pkgs) {
			end = len(pkgs)
		}
		chunk := pkgs[start:end]

		type pkgQ struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		}
		type query struct {
			Version string `json:"version"`
			Package pkgQ   `json:"package"`
		}
		queries := make([]query, len(chunk))
		for i, p := range chunk {
			queries[i] = query{Version: p.Version, Package: pkgQ{Name: p.Name, Ecosystem: ecosystem}}
		}
		body, err := json.Marshal(map[string]any{"queries": queries})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvBatchURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		var out struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		err = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("osv querybatch returned %s", resp.Status)
		}
		if len(out.Results) != len(chunk) {
			return nil, fmt.Errorf("osv returned %d results for %d queries", len(out.Results), len(chunk))
		}
		for i, r := range out.Results {
			for _, v := range r.Vulns {
				found = append(found, model.Vulnerability{
					ID:      v.ID,
					Package: chunk[i].Name,
					Version: chunk[i].Version,
				})
			}
		}
	}
	return found, nil
}

// fetchVulnDetails fills the details cache for newly seen vuln IDs, a capped
// number per call; returns true when the queue is empty.
func (s *Server) fetchVulnDetails(ctx context.Context) bool {
	ids, err := s.store.UnknownVulnIDs(ctx, detailFetchCap)
	if err != nil || len(ids) == 0 {
		return true
	}
	client := &http.Client{Timeout: 20 * time.Second}
	for _, id := range ids {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, osvVulnURL+id, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			return false // network trouble: try again next cycle
		}
		var detail struct {
			Summary  string `json:"summary"`
			Details  string `json:"details"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			DatabaseSpecific map[string]any `json:"database_specific"`
		}
		err = json.NewDecoder(resp.Body).Decode(&detail)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			// Cache a placeholder so one bad record doesn't block the queue.
			s.store.SetVulnDetail(ctx, id, "", "")
			continue
		}
		severity := ""
		if sv, ok := detail.DatabaseSpecific["severity"].(string); ok {
			severity = sv
		} else if len(detail.Severity) > 0 {
			severity = detail.Severity[0].Score // CVSS vector string
		}
		summary := detail.Summary
		if summary == "" {
			summary = detail.Details
		}
		if len(summary) > 240 {
			summary = summary[:240] + "…"
		}
		summary = strings.ReplaceAll(summary, "\n", " ")
		s.store.SetVulnDetail(ctx, id, severity, summary)
	}
	s.log.Info("vulnerability details cached", "count", len(ids))
	return len(ids) < detailFetchCap
}

// handleEndpointVulns returns an endpoint's current findings.
func (s *Server) handleEndpointVulns(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	id, ok := s.endpointInScope(w, r, scope)
	if !ok {
		return
	}
	vulns, err := s.store.EndpointVulns(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if vulns == nil {
		vulns = []model.Vulnerability{}
	}
	scannedAt, _, _ := s.store.VulnScanState(r.Context(), id)
	supported := false
	if inv, _, err := s.store.Inventory(r.Context(), id); err == nil && inv != nil {
		eps, _ := s.store.Endpoints(r.Context(), nil)
		platform := ""
		for _, ep := range eps {
			if ep.ID == id {
				platform = ep.Platform
				break
			}
		}
		supported = osvEcosystem(inv.Manager, platform) != ""
	}
	writeJSON(w, map[string]any{
		"supported":  supported,
		"scanned_at": time.Unix(scannedAt, 0).UTC(),
		"count":      len(vulns),
		"vulns":      vulns,
	})
}
