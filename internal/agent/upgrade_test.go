package agent

import "testing"

func TestShouldUpgrade(t *testing.T) {
	cases := []struct {
		current, desired string
		want             bool
	}{
		{"v0.4.1", "v0.4.2", true},
		{"0.4.1", "v0.4.2", true},   // bare current vs tagged desired
		{"v0.4.2", "0.4.2", false},  // same version, mixed prefixes
		{"v0.4.2", "v0.4.1", true},  // rollback is a valid upgrade direction
		{"dev", "v0.4.2", false},    // dev builds never self-replace
		{"v0.4.1", "dev", false},    // never "upgrade" to a dev version
		{"v0.4.1", "", false},       // upgrades disabled server-side
		{"", "v0.4.2", false},
	}
	for _, c := range cases {
		if got := shouldUpgrade(c.current, c.desired); got != c.want {
			t.Errorf("shouldUpgrade(%q, %q) = %v, want %v", c.current, c.desired, got, c.want)
		}
	}
}

func TestParseChecksum(t *testing.T) {
	body := []byte(`abc123  varro-linux-amd64
def456  varro-linux-arm64
789fed  checksums-decoy varro-linux-amd64
`)
	if got := parseChecksum(body, "varro-linux-amd64"); got != "abc123" {
		t.Errorf("got %q, want abc123", got)
	}
	if got := parseChecksum(body, "varro-darwin-arm64"); got != "" {
		t.Errorf("missing asset should return empty, got %q", got)
	}
}
