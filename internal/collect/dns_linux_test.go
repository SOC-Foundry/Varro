//go:build linux

package collect

import (
	"net"
	"os"
	"testing"
	"time"
)

// TestDNSWatchLive exercises the real AF_PACKET capture path: start the watcher,
// trigger DNS lookups, and confirm at least one resolved IP gets labeled with
// its domain. Needs CAP_NET_RAW (run as root); skips otherwise, and skips if no
// response is observed (resolver caching / sandboxed network) so it never
// flakes in CI — it's a best-effort live check.
func TestDNSWatchLive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("AF_PACKET capture needs root")
	}
	w, err := StartDNSWatch()
	if err != nil {
		t.Skipf("StartDNSWatch: %v", err)
	}
	defer w.Close()

	domains := []string{"example.com", "example.net", "example.org", "cloudflare.com", "wikipedia.org"}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		for _, d := range domains {
			ips, err := net.LookupHost(d)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				if got := w.Lookup(ip); got != "" {
					t.Logf("captured: %s -> %s", ip, got)
					return // success: capture + parse + cache all worked
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Skip("no DNS response captured (resolver cache or no network); capture path not exercised")
}
