//go:build linux

package agent

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strings"
)

// collectorIPs resolves the collector hostname to IPs so isolation can keep
// the agent->collector channel open while dropping everything else.
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

// isolateHost installs an nftables ruleset that drops all traffic except
// loopback, DNS, established flows, and the collector. Varro's own
// "varro_isolate" table is used so unisolate is a clean teardown.
func isolateHost(ctx context.Context, serverURL string) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nftables (nft) required for isolation")
	}
	ips, err := collectorIPs(serverURL)
	if err != nil {
		return fmt.Errorf("resolve collector: %w", err)
	}
	var allow strings.Builder
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			continue // v4 ruleset below; v6 collector would need an ip6 table
		}
		fmt.Fprintf(&allow, "ip daddr %s accept\n", ip)
		fmt.Fprintf(&allow, "ip saddr %s accept\n", ip)
	}
	ruleset := `table inet varro_isolate {
	chain output {
		type filter hook output priority -100; policy drop;
		oif "lo" accept
		ct state established,related accept
		udp dport 53 accept
		tcp dport 53 accept
` + indent(allow.String()) + `	}
	chain input {
		type filter hook input priority -100; policy drop;
		iif "lo" accept
		ct state established,related accept
` + indent(allow.String()) + `	}
}
`
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func unisolateHost(ctx context.Context) error {
	// Removing our dedicated table restores normal networking; ignore "no
	// such table" so unisolate is idempotent.
	out, err := exec.CommandContext(ctx, "nft", "delete", "table", "inet", "varro_isolate").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such file") {
		return fmt.Errorf("nft delete: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if line != "" {
			b.WriteString("\t\t" + line + "\n")
		}
	}
	return b.String()
}
