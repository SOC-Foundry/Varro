package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"
)

const geoTTL = 24 * time.Hour

type geoEntry struct {
	label    string // "US/AS15169 Google" style
	resolved time.Time
}

// geoCache resolves public IPs to country + ASN, lazily and off the request
// path (same pattern as rDNS). Opt-in: enabled only when a GeoIP source is
// configured, because it sends observed remote IPs to a third-party service.
type geoCache struct {
	mu      sync.Mutex
	entries map[string]geoEntry
	queued  map[string]bool
	api     string // endpoint template with %s for the IP
}

func newGeoCache(api string) *geoCache {
	if api == "" {
		// ip-api.com: free, no key, returns country + ASN. Only used when
		// GeoIP is explicitly enabled.
		api = "http://ip-api.com/json/%s?fields=status,countryCode,as"
	}
	return &geoCache{entries: map[string]geoEntry{}, queued: map[string]bool{}, api: api}
}

func (g *geoCache) label(ip string) string {
	p := net.ParseIP(ip)
	if p == nil || p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() {
		return ""
	}
	g.mu.Lock()
	e, ok := g.entries[ip]
	fresh := ok && time.Since(e.resolved) < geoTTL
	if !fresh && !g.queued[ip] {
		g.queued[ip] = true
		go g.resolve(ip)
	}
	g.mu.Unlock()
	if fresh {
		return e.label
	}
	return ""
}

func (g *geoCache) resolve(ip string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	label := ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		sprintfURL(g.api, ip), nil)
	if err == nil {
		if resp, err := http.DefaultClient.Do(req); err == nil {
			var out struct {
				Status      string `json:"status"`
				CountryCode string `json:"countryCode"`
				AS          string `json:"as"`
			}
			json.NewDecoder(resp.Body).Decode(&out)
			resp.Body.Close()
			if out.Status == "success" {
				label = out.CountryCode
				if out.AS != "" {
					label += " · " + out.AS
				}
			}
		}
	}
	g.mu.Lock()
	g.entries[ip] = geoEntry{label: label, resolved: time.Now()}
	delete(g.queued, ip)
	g.mu.Unlock()
}

func sprintfURL(tmpl, ip string) string {
	// tmpl contains exactly one %s; avoid fmt to keep the IP un-reinterpreted.
	for i := 0; i+1 < len(tmpl); i++ {
		if tmpl[i] == '%' && tmpl[i+1] == 's' {
			return tmpl[:i] + ip + tmpl[i+2:]
		}
	}
	return tmpl
}
