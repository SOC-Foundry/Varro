//go:build windows

package agent

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// isolRuleName labels every firewall rule we add so unisolate can remove the
// whole set in one call (netsh deletes all rules sharing a name).
const isolRuleName = "Varro Isolate"

// isolateHost contains a Windows host with the built-in firewall (netsh
// advfirewall). It adds allow rules for the agent->collector channel and DNS,
// then flips the default outbound policy to block so nothing else can leave.
// The agent runs as the LocalSystem service account, which has rights to manage
// the firewall.
func isolateHost(ctx context.Context, serverURL string) error {
	ips, err := collectorIPs(serverURL)
	if err != nil {
		return fmt.Errorf("resolve collector: %w", err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("no collector IPs resolved; refusing to isolate")
	}
	if _, err := exec.LookPath("netsh"); err != nil {
		return fmt.Errorf("netsh not available for isolation")
	}
	run := func(args ...string) error {
		out, err := exec.CommandContext(ctx, "netsh", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("netsh %v: %s", args, strings.TrimSpace(string(out)))
		}
		return nil
	}

	// Clear any stale ruleset first (ignore "no rules match").
	exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+isolRuleName).Run()

	remoteIPs := strings.Join(ips, ",")
	// Add allow rules BEFORE blocking by default so the agent's live connection
	// to the collector is never cut mid-apply. remoteip accepts a comma list and
	// handles both v4 and v6 literals.
	adds := [][]string{
		{"advfirewall", "firewall", "add", "rule", "name=" + isolRuleName,
			"dir=out", "action=allow", "remoteip=" + remoteIPs},
		{"advfirewall", "firewall", "add", "rule", "name=" + isolRuleName,
			"dir=in", "action=allow", "remoteip=" + remoteIPs},
		{"advfirewall", "firewall", "add", "rule", "name=" + isolRuleName,
			"dir=out", "action=allow", "protocol=UDP", "remoteport=53"},
		{"advfirewall", "firewall", "add", "rule", "name=" + isolRuleName,
			"dir=out", "action=allow", "protocol=TCP", "remoteport=53"},
	}
	for _, a := range adds {
		if err := run(a...); err != nil {
			return err
		}
	}
	// Flip every profile to block inbound and outbound by default; loopback
	// stays permitted implicitly.
	return run("advfirewall", "set", "allprofiles", "firewallpolicy",
		"blockinbound,blockoutbound")
}

// unisolateHost restores the Windows default outbound policy and removes our
// allow rules. Policy is restored first so connectivity returns immediately;
// both steps are best-effort for idempotent teardown.
func unisolateHost(ctx context.Context) error {
	if _, err := exec.LookPath("netsh"); err != nil {
		return fmt.Errorf("netsh not available")
	}
	exec.CommandContext(ctx, "netsh", "advfirewall", "set", "allprofiles",
		"firewallpolicy", "blockinbound,allowoutbound").Run()
	exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+isolRuleName).Run()
	return nil
}
