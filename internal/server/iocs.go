package server

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// normalizeIOC validates and canonicalizes an indicator by type. IPs must parse;
// domains are lowercased/dotted; hashes must be 64-hex (SHA-256).
func normalizeIOC(iocType, value string) (string, string, bool) {
	iocType = strings.ToLower(strings.TrimSpace(iocType))
	value = strings.TrimSpace(value)
	switch iocType {
	case model.IOCTypeIP:
		if net.ParseIP(value) == nil {
			return "", "", false
		}
		return iocType, value, true
	case model.IOCTypeDomain:
		d := normalizeDomain(value)
		if d == "" {
			return "", "", false
		}
		return iocType, d, true
	case model.IOCTypeHash:
		h := strings.ToLower(value)
		if len(h) != 64 || !isHex(h) {
			return "", "", false
		}
		return iocType, h, true
	}
	return "", "", false
}

// handleIOCList returns an org's indicators + per-type counts (org admin).
func (s *Server) handleIOCList(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	iocs, err := s.store.ListIOCs(r.Context(), orgID, r.URL.Query().Get("type"), r.URL.Query().Get("q"), 1000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if iocs == nil {
		iocs = []model.IOC{}
	}
	counts, _ := s.store.CountIOCs(r.Context(), orgID)
	writeJSON(w, map[string]any{"iocs": iocs, "counts": counts})
}

// handleIOCCreate adds one manual indicator (org admin).
func (s *Server) handleIOCCreate(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	var req struct {
		Type  string `json:"type"`
		Value string `json:"value"`
		Label string `json:"label"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	t, v, valid := normalizeIOC(req.Type, req.Value)
	if !valid {
		http.Error(w, "value is not a valid "+req.Type+" (ip, domain, or 64-hex sha256 hash)", http.StatusBadRequest)
		return
	}
	n, err := s.store.UpsertIOCs(r.Context(), orgID, []model.IOC{{
		Type: t, Value: v, Source: "manual", Label: strings.TrimSpace(req.Label), AddedAt: time.Now().Unix(),
	}})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.reloadCustomIOCs(r.Context())
	s.audit(r, "ioc.create", orgID, t+":"+v)
	writeJSON(w, map[string]any{"added": n, "type": t, "value": v})
}

// handleIOCDelete removes one indicator (org admin). The indicator is identified
// by ?type= and ?value= query params.
func (s *Server) handleIOCDelete(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	iocType := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
	value := strings.TrimSpace(r.URL.Query().Get("value"))
	if iocType == "" || value == "" {
		http.Error(w, "type and value query params are required", http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteIOC(r.Context(), orgID, iocType, value); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.reloadCustomIOCs(r.Context())
	s.audit(r, "ioc.delete", orgID, iocType+":"+value)
	writeJSON(w, map[string]bool{"removed": true})
}

// handleSTIXFeedList returns an org's configured feeds (org admin).
func (s *Server) handleSTIXFeedList(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	feeds, err := s.store.ListSTIXFeeds(r.Context(), orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if feeds == nil {
		feeds = []model.STIXFeed{}
	}
	writeJSON(w, map[string]any{"feeds": feeds})
}

// handleSTIXFeedCreate adds a STIX/TAXII feed (org admin). The URL must be http(s);
// SSRF to internal addresses is blocked at fetch time by the guarded client.
func (s *Server) handleSTIXFeedCreate(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	var req struct {
		URL  string `json:"url"`
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	u, err := url.Parse(req.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		http.Error(w, "url must be a valid http(s) URL", http.StatusBadRequest)
		return
	}
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if kind != "taxii" {
		kind = "stix"
	}
	created, err := s.store.AddSTIXFeed(r.Context(), model.STIXFeed{
		OrgID: orgID, URL: req.URL, Kind: kind, Enabled: true, AddedAt: time.Now().Unix(),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "stix.feed.create", orgID, redactURL(req.URL))
	// Poll it immediately (async, own context) so the operator sees results
	// without waiting for the next refresh cycle; the request context is gone by
	// the time this runs.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		s.refreshSTIXFeed(ctx, created)
	}()
	writeJSON(w, created)
}

// handleSTIXFeedDelete removes a feed; already-ingested IOCs remain (org admin).
func (s *Server) handleSTIXFeedDelete(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteSTIXFeed(r.Context(), orgID, r.PathValue("fid")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, "stix.feed.delete", orgID, r.PathValue("fid"))
	writeJSON(w, map[string]bool{"removed": true})
}

// handleSTIXFeedRefresh polls one feed now (org admin).
func (s *Server) handleSTIXFeedRefresh(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	f, err := s.store.GetSTIXFeed(r.Context(), orgID, r.PathValue("fid"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.refreshSTIXFeed(r.Context(), *f)
	updated, _ := s.store.GetSTIXFeed(r.Context(), orgID, f.ID)
	if updated == nil {
		updated = f
	}
	writeJSON(w, updated)
}

// handleSTIXIngest parses a pasted/uploaded STIX bundle (or TAXII envelope) and
// upserts its indicators as IOCs (org admin) — for feeds behind auth the server
// can't poll, or one-off imports.
func (s *Server) handleSTIXIngest(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(http.MaxBytesReader(w, r.Body, maxSTIXBody), maxSTIXBody))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	iocs := parseSTIXIndicators(body, "import", time.Now().Unix())
	if len(iocs) == 0 {
		http.Error(w, "no indicators found — expected a STIX 2.1 bundle or TAXII envelope with ipv4-addr/domain-name/url/file:SHA-256 patterns", http.StatusBadRequest)
		return
	}
	n, err := s.store.UpsertIOCs(r.Context(), orgID, iocs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.reloadCustomIOCs(r.Context())
	s.audit(r, "stix.ingest", orgID, itoa(n)+" indicators")
	writeJSON(w, map[string]any{"ingested": n})
}
