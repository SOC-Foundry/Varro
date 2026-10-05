//go:build darwin

package agent

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// isolateHost contains a macOS host with pf. It loads a minimal ruleset that
// drops everything except loopback, DNS, and the agent->collector channel, then
// enables pf. Replacing the active ruleset (rather than relying on a named
// anchor, which only runs if /etc/pf.conf references it) guarantees the rules
// take effect without editing the system config.
func isolateHost(ctx context.Context, serverURL string) error {
	ips, err := collectorIPs(serverURL)
	if err != nil {
		return fmt.Errorf("resolve collector: %w", err)
	}
	if _, err := exec.LookPath("pfctl"); err != nil {
		return fmt.Errorf("pfctl not available for isolation")
	}
	ruleset := pfRuleset(ips)

	// Load the ruleset, then enable pf. "-e" is a no-op error if pf is already
	// on, which we tolerate.
	load := exec.CommandContext(ctx, "pfctl", "-f", "-")
	load.Stdin = strings.NewReader(ruleset)
	if out, err := load.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl load: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "pfctl", "-e").CombinedOutput(); err != nil &&
		!strings.Contains(string(out), "already enabled") {
		return fmt.Errorf("pfctl enable: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// pfRuleset builds the pf ruleset that contains the host while preserving the
// agent->collector channel and DNS. Split out so it can be validated with
// "pfctl -n" in tests without actually loading rules.
func pfRuleset(ips []string) string {
	var b strings.Builder
	// skip on lo0 keeps loopback fully open; block-policy drop makes denied
	// traffic fail fast instead of hanging.
	b.WriteString("set block-policy drop\n")
	b.WriteString("set skip on lo0\n")
	b.WriteString("block all\n")
	for _, ip := range ips {
		// flags any keep state so the agent's already-established socket (no SYN
		// in flight) is matched and preserved, not just new connections. pf
		// accepts bracketless v4 and v6 literals in "to <host>" as-is.
		fmt.Fprintf(&b, "pass out quick proto tcp to %s flags any keep state\n", ip)
		fmt.Fprintf(&b, "pass in quick proto tcp from %s flags any keep state\n", ip)
	}
	// DNS out so the collector hostname can be re-resolved while contained.
	b.WriteString("pass out quick proto udp to any port 53 keep state\n")
	b.WriteString("pass out quick proto tcp to any port 53 flags any keep state\n")
	return b.String()
}

// unisolateHost restores the stock macOS ruleset and disables pf (the system
// default). Both steps are best-effort so teardown is idempotent.
func unisolateHost(ctx context.Context) error {
	if _, err := exec.LookPath("pfctl"); err != nil {
		return fmt.Errorf("pfctl not available")
	}
	exec.CommandContext(ctx, "pfctl", "-f", "/etc/pf.conf").Run()
	if out, err := exec.CommandContext(ctx, "pfctl", "-d").CombinedOutput(); err != nil &&
		!strings.Contains(string(out), "not enabled") {
		return fmt.Errorf("pfctl disable: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
