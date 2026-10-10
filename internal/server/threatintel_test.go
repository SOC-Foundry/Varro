package server

import "testing"

func TestIsBadDomain(t *testing.T) {
	ti := newThreatIntel(nil, nil, nil)
	ti.badDomains = map[string]bool{
		"evil.example":      true,
		"bad.co.uk":         true,
		"exact.malware.net": true,
	}

	cases := []struct {
		domain string
		want   bool
	}{
		{"evil.example", true},              // exact
		{"login.evil.example", true},        // subdomain of listed
		{"a.b.evil.example", true},          // deeper subdomain
		{"exact.malware.net", true},         // exact
		{"malware.net", false},              // parent of a listed host is NOT bad
		{"notevil.example", false},          // sibling, not a subdomain
		{"evil.example.com", false},         // different apex
		{"example", false},                  // bare label
		{"", false},                         // empty
		{"GOOD.com", false},                 // unlisted
		{"bad.co.uk", true},                 // exact multi-level
		{"www.bad.co.uk", true},             // subdomain
	}
	for _, c := range cases {
		if got := ti.isBadDomain(c.domain); got != c.want {
			t.Errorf("isBadDomain(%q) = %v, want %v", c.domain, got, c.want)
		}
	}
}

func TestIsBadDomainEmptySet(t *testing.T) {
	ti := newThreatIntel(nil, nil, nil)
	if ti.isBadDomain("anything.com") {
		t.Fatal("empty indicator set must never match")
	}
}
