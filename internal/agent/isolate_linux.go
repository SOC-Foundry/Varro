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

// isolateHost drops all traffic except loopback, DNS, established flows, and
// the collector. It prefers nftables (a dedicated "varro_isolate" table for
// clean teardown) and falls back to iptables where the nft CLI is absent.
func isolateHost(ctx context.Context, serverURL string) error {
	ips, err := collectorIPs(serverURL)
	if err != nil {
		return fmt.Errorf("resolve collector: %w", err)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return isolateIptables(ctx, ips)
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
	if _, err := exec.LookPath("nft"); err != nil {
		return unisolateIptables(ctx)
	}
	// Removing our dedicated table restores normal networking; ignore "no
	// such table" so unisolate is idempotent.
	out, err := exec.CommandContext(ctx, "nft", "delete", "table", "inet", "varro_isolate").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such file") {
		return fmt.Errorf("nft delete: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// --- iptables fallback (uses a dedicated VARRO-ISOLATE chain per direction) ---

func isolateIptables(ctx context.Context, ips []string) error {
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("neither nft nor iptables available for isolation")
	}
	run := func(args ...string) error {
		out, err := exec.CommandContext(ctx, "iptables", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables %v: %s", args, strings.TrimSpace(string(out)))
		}
		return nil
	}
	// Start clean, then build allow-rules ending in a DROP, and jump OUTPUT/
	// INPUT at them.
	unisolateIptables(ctx)
	for _, chain := range []string{"VARRO-ISOLATE-OUT", "VARRO-ISOLATE-IN"} {
		if err := run("-N", chain); err != nil {
			return err
		}
	}
	rules := [][]string{
		{"-A", "VARRO-ISOLATE-OUT", "-o", "lo", "-j", "ACCEPT"},
		{"-A", "VARRO-ISOLATE-OUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-A", "VARRO-ISOLATE-OUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
		{"-A", "VARRO-ISOLATE-OUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
		{"-A", "VARRO-ISOLATE-IN", "-i", "lo", "-j", "ACCEPT"},
		{"-A", "VARRO-ISOLATE-IN", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			continue
		}
		rules = append(rules,
			[]string{"-A", "VARRO-ISOLATE-OUT", "-d", ip, "-j", "ACCEPT"},
			[]string{"-A", "VARRO-ISOLATE-IN", "-s", ip, "-j", "ACCEPT"})
	}
	rules = append(rules,
		[]string{"-A", "VARRO-ISOLATE-OUT", "-j", "DROP"},
		[]string{"-A", "VARRO-ISOLATE-IN", "-j", "DROP"},
		[]string{"-I", "OUTPUT", "1", "-j", "VARRO-ISOLATE-OUT"},
		[]string{"-I", "INPUT", "1", "-j", "VARRO-ISOLATE-IN"})
	for _, r := range rules {
		if err := run(r...); err != nil {
			return err
		}
	}
	return nil
}

func unisolateIptables(ctx context.Context) error {
	if _, err := exec.LookPath("iptables"); err != nil {
		return nil
	}
	// Detach the jumps, then flush and delete our chains. All best-effort so
	// teardown is idempotent regardless of current state.
	cmds := [][]string{
		{"-D", "OUTPUT", "-j", "VARRO-ISOLATE-OUT"},
		{"-D", "INPUT", "-j", "VARRO-ISOLATE-IN"},
		{"-F", "VARRO-ISOLATE-OUT"},
		{"-F", "VARRO-ISOLATE-IN"},
		{"-X", "VARRO-ISOLATE-OUT"},
		{"-X", "VARRO-ISOLATE-IN"},
	}
	for _, c := range cmds {
		exec.CommandContext(ctx, "iptables", c...).Run()
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
