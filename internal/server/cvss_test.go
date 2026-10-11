package server

import (
	"math"
	"testing"
)

func TestCVSSv3BaseScore(t *testing.T) {
	// Canonical vectors with their official v3.1 base scores.
	cases := []struct {
		vec  string
		want float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8}, // RCE, unauth
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8}, // local priv-esc
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5}, // network DoS
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9}, // high-complexity DoS
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 9.6}, // scope-changed
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8}, // v3.0 same formula
	}
	for _, c := range cases {
		got, ok := cvssBaseScore(c.vec)
		if !ok {
			t.Errorf("%s: not recognized", c.vec)
			continue
		}
		if math.Abs(got-c.want) > 0.05 {
			t.Errorf("%s: score = %.1f, want %.1f", c.vec, got, c.want)
		}
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		// Qualitative labels (GHSA / distro style).
		"HIGH":     "high",
		"Moderate": "medium",
		"critical": "critical",
		"low":      "low",
		"":         "unknown",
		"garbage":  "unknown",
		// CVSS vectors (what Debian/OSV actually store).
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": "critical",
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": "high",
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H": "medium",
		"CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N": "low",
		// v2 vector (no CVSS: prefix, has Au).
		"AV:N/AC:L/Au:N/C:P/I:P/A:P": "high",
		// v4 vector (approximated).
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": "critical",
	}
	for raw, want := range cases {
		if got := normalizeSeverity(raw); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", raw, got, want)
		}
	}
}
