package agent

import (
	"net"
	"net/url"
)

// collectorIPs resolves the collector hostname to IPs so host isolation can
// keep the agent->collector channel open while dropping everything else. It is
// shared by every platform's isolateHost implementation.
func collectorIPs(serverURL string) ([]string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, err
	}
	ips, err := net.LookupHost(u.Hostname())
	if err != nil {
		return nil, err
	}
	return ips, nil
}
