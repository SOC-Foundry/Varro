//go:build !linux

package collect

import "errors"

// DNSWatcher is a no-op on non-Linux platforms; passive DNS capture via
// AF_PACKET is Linux-only for now. The agent falls back to reverse-DNS labels.
type DNSWatcher struct{}

func StartDNSWatch() (*DNSWatcher, error) {
	return nil, errors.New("passive DNS capture is only implemented on Linux")
}

func (w *DNSWatcher) Lookup(string) string { return "" }
func (w *DNSWatcher) Close() error         { return nil }
