//go:build darwin

package agent

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestPfRulesetParses validates that the isolation ruleset we generate is
// accepted by the real macOS pf parser. "pfctl -n" parses and checks the
// ruleset WITHOUT loading it, so this never touches live networking. Requires
// root (CI runs it under sudo); skipped otherwise.
func TestPfRulesetParses(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("pfctl requires root; run under sudo")
	}
	if _, err := exec.LookPath("pfctl"); err != nil {
		t.Skip("pfctl not available")
	}
	// Mix of IPv4 and IPv6 collector addresses to exercise both rule forms.
	rs := pfRuleset([]string{"203.0.113.10", "198.51.100.7", "2001:db8::1"})
	cmd := exec.Command("pfctl", "-n", "-f", "-")
	cmd.Stdin = strings.NewReader(rs)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pfctl rejected generated ruleset: %v\n--- ruleset ---\n%s\n--- pfctl output ---\n%s",
			err, rs, out)
	}
}
