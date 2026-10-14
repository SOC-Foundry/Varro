package server

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

const (
	stixRefreshEvery = 6 * time.Hour
	maxSTIXBody      = 64 << 20 // 64 MiB — feeds can be large bundles
)

// STIX 2.1 pattern extractors. Patterns look like
//
//	[ipv4-addr:value = '1.2.3.4']
//	[domain-name:value = 'evil.example' OR domain-name:value = 'bad.example']
//	[file:hashes.'SHA-256' = '<64 hex>']
//
// We scan for every object-path = 'value' occurrence so AND/OR-combined patterns
// all contribute. Only SHA-256 hashes are ingested (what the binary-hash matcher
// compares against).
var (
	stixIPRe   = regexp.MustCompile(`(?:ipv4|ipv6)-addr:value\s*=\s*'([^']+)'`)
	stixDomRe  = regexp.MustCompile(`domain-name:value\s*=\s*'([^']+)'`)
	stixURLRe  = regexp.MustCompile(`url:value\s*=\s*'([^']+)'`)
	stixHashRe = regexp.MustCompile(`file:hashes\.(?:'SHA-256'|"SHA-256"|SHA-?256)\s*=\s*'([a-fA-F0-9]{64})'`)
)

// stixObject is the minimal subset of a STIX 2.x SDO/SCO we read.
type stixObject struct {
	Type        string            `json:"type"`
	Pattern     string            `json:"pattern"`
	PatternType string            `json:"pattern_type"`
	Value       string            `json:"value"`  // for raw SCOs (ipv4-addr, domain-name, url)
	Hashes      map[string]string `json:"hashes"` // for raw file SCOs
}

// stixEnvelope covers both a STIX bundle ({"type":"bundle","objects":[…]}) and a
// TAXII 2.1 envelope ({"objects":[…],"more":…}) — both expose "objects".
type stixEnvelope struct {
	Objects []stixObject `json:"objects"`
}

// parseSTIXIndicators turns a STIX bundle / TAXII envelope JSON blob into IOCs,
// de-duplicated and normalized. Unknown object/pattern shapes are skipped.
func parseSTIXIndicators(body []byte, source string, now int64) []model.IOC {
	var env stixEnvelope
	if err := json.Unmarshal(body, &env); err != nil || len(env.Objects) == 0 {
		return nil
	}
	seen := map[string]bool{} // type|value
	var out []model.IOC
	add := func(t, v string) {
		if v == "" {
			return
		}
		k := t + "|" + v
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, model.IOC{Type: t, Value: v, Source: source, AddedAt: now})
	}
	for _, o := range env.Objects {
		switch o.Type {
		case "indicator":
			for _, m := range stixIPRe.FindAllStringSubmatch(o.Pattern, -1) {
				if ip := strings.TrimSpace(m[1]); net.ParseIP(ip) != nil {
					add(model.IOCTypeIP, ip)
				}
			}
			for _, m := range stixDomRe.FindAllStringSubmatch(o.Pattern, -1) {
				if d := normalizeDomain(m[1]); d != "" {
					add(model.IOCTypeDomain, d)
				}
			}
			for _, m := range stixURLRe.FindAllStringSubmatch(o.Pattern, -1) {
				if d := hostFromURL(m[1]); d != "" {
					add(model.IOCTypeDomain, d)
				}
			}
			for _, m := range stixHashRe.FindAllStringSubmatch(o.Pattern, -1) {
				add(model.IOCTypeHash, strings.ToLower(m[1]))
			}
		case "ipv4-addr", "ipv6-addr":
			if net.ParseIP(strings.TrimSpace(o.Value)) != nil {
				add(model.IOCTypeIP, strings.TrimSpace(o.Value))
			}
		case "domain-name":
			if d := normalizeDomain(o.Value); d != "" {
				add(model.IOCTypeDomain, d)
			}
		case "url":
			if d := hostFromURL(o.Value); d != "" {
				add(model.IOCTypeDomain, d)
			}
		case "file":
			for alg, h := range o.Hashes {
				if a := strings.ToUpper(strings.ReplaceAll(alg, "-", "")); a == "SHA256" && len(h) == 64 && isHex(strings.ToLower(h)) {
					add(model.IOCTypeHash, strings.ToLower(h))
				}
			}
		}
	}
	return out
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
	if d == "" || !strings.Contains(d, ".") || net.ParseIP(d) != nil {
		return ""
	}
	return d
}

func hostFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return normalizeDomain(u.Hostname())
}

// fetchSTIXFeed downloads a feed's JSON, SSRF-guarded (admin-supplied URL is
// semi-trusted tenant input, same policy as webhooks/synthetic probes). The TAXII
// Accept header is sent for taxii feeds; servers ignore it for plain bundles.
func (s *Server) fetchSTIXFeed(ctx context.Context, f model.STIXFeed) ([]byte, error) {
	infra, _ := s.store.OrgIsInfrastructure(ctx, f.OrgID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	if f.Kind == "taxii" {
		req.Header.Set("Accept", "application/taxii+json;version=2.1")
	} else {
		req.Header.Set("Accept", "application/stix+json;version=2.1, application/json")
	}
	client := s.guardedClient(infra)
	client.Timeout = 60 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &feedError{status: resp.StatusCode}
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxSTIXBody))
}

type feedError struct{ status int }

func (e *feedError) Error() string { return "feed returned HTTP " + itoa(e.status) }

// refreshSTIXFeed polls one feed, upserts its IOCs, and records the outcome.
func (s *Server) refreshSTIXFeed(ctx context.Context, f model.STIXFeed) {
	now := time.Now()
	body, err := s.fetchSTIXFeed(ctx, f)
	if err != nil {
		s.log.Error("stix feed fetch failed", "url", redactURL(f.URL), "error", err)
		s.store.UpdateSTIXFeedStatus(ctx, f.ID, now.Unix(), 0, "error: "+err.Error())
		return
	}
	iocs := parseSTIXIndicators(body, f.URL, now.Unix())
	n, err := s.store.UpsertIOCs(ctx, f.OrgID, iocs)
	if err != nil {
		s.log.Error("stix feed upsert failed", "url", redactURL(f.URL), "error", err)
		s.store.UpdateSTIXFeedStatus(ctx, f.ID, now.Unix(), 0, "error: storage")
		return
	}
	s.store.UpdateSTIXFeedStatus(ctx, f.ID, now.Unix(), n, "ok")
	s.log.Info("stix feed ingested", "url", redactURL(f.URL), "org", f.OrgID, "indicators", n)
	s.reloadCustomIOCs(ctx) // make freshly-ingested IOCs matchable now
}

// customIOCReloadLoop refreshes the in-memory per-org IOC overlay from the DB on
// every collector, so indicators the leader ingested (or another node's admin
// added) become matchable cluster-wide without a restart.
func (s *Server) customIOCReloadLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.reloadCustomIOCs(ctx)
		}
	}
}

// stixRefreshLoop polls all enabled feeds now and every stixRefreshEvery
// (leader-only, so the shared DB isn't hit by every collector).
func (s *Server) stixRefreshLoop(ctx context.Context) {
	run := func() {
		if !s.isLeader() {
			return
		}
		feeds, err := s.store.AllEnabledSTIXFeeds(ctx)
		if err != nil {
			s.log.Error("stix: list feeds", "error", err)
			return
		}
		for _, f := range feeds {
			s.refreshSTIXFeed(ctx, f)
		}
	}
	run()
	t := time.NewTicker(stixRefreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
