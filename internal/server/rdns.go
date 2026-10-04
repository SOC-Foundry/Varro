package server

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// rdnsTTL is how long a reverse-DNS result (including a negative result) is
// trusted before re-resolution.
const rdnsTTL = 6 * time.Hour

type rdnsEntry struct {
	name     string // "" = resolved to nothing (negative cache)
	resolved time.Time
}

// rdnsCache resolves IPs to hostnames lazily and off the request path: a
// lookup returns whatever is cached immediately and queues a resolve for
// anything missing or stale, so the dashboard fills in names over a few
// seconds rather than blocking.
type rdnsCache struct {
	mu       sync.Mutex
	entries  map[string]rdnsEntry
	queued   map[string]bool
	resolver *net.Resolver
}

func newRDNSCache() *rdnsCache {
	return &rdnsCache{
		entries:  map[string]rdnsEntry{},
		queued:   map[string]bool{},
		resolver: &net.Resolver{},
	}
}

// name returns the cached hostname for an IP ("" if unknown), scheduling a
// background resolve when the entry is missing or stale. Private and special
// addresses are never looked up.
func (c *rdnsCache) name(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() {
		return ""
	}
	c.mu.Lock()
	e, ok := c.entries[ip]
	fresh := ok && time.Since(e.resolved) < rdnsTTL
	if !fresh && !c.queued[ip] {
		c.queued[ip] = true
		go c.resolve(ip)
	}
	c.mu.Unlock()
	if fresh {
		return e.name
	}
	return ""
}

func (c *rdnsCache) resolve(ip string) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var name string
	if names, err := c.resolver.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}
	c.mu.Lock()
	c.entries[ip] = rdnsEntry{name: name, resolved: time.Now()}
	delete(c.queued, ip)
	c.mu.Unlock()
}
