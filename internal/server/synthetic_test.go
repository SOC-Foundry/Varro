package server

import (
	"net"
	"testing"
)

func TestAllowedProbeIP(t *testing.T) {
	cases := []struct {
		ip        string
		infra     bool
		wantAllow bool
	}{
		// Cloud metadata + link-local: blocked for everyone, infra included.
		{"169.254.169.254", false, false},
		{"169.254.169.254", true, false},
		{"169.254.1.1", true, false},
		{"fe80::1", true, false},
		// Loopback: infra only.
		{"127.0.0.1", false, false},
		{"127.0.0.1", true, true},
		{"::1", false, false},
		// Private ranges: infra only.
		{"10.128.0.10", false, false},
		{"10.128.0.10", true, true},
		{"192.168.1.1", false, false},
		{"172.16.5.5", false, false},
		// CGNAT + reserved ranges IsPrivate() misses: infra only.
		{"100.64.0.1", false, false},
		{"100.64.0.1", true, true},
		{"198.18.0.1", false, false},
		{"240.0.0.1", false, false},
		// Public: allowed for everyone.
		{"1.1.1.1", false, true},
		{"8.8.8.8", false, true},
		{"93.184.216.34", false, true},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", c.ip)
		}
		err := allowedProbeIP(c.infra, ip)
		if (err == nil) != c.wantAllow {
			t.Errorf("allowedProbeIP(%s, infra=%v) allowed=%v, want %v (err=%v)",
				c.ip, c.infra, err == nil, c.wantAllow, err)
		}
	}
}

func TestValidateCheck(t *testing.T) {
	ok := []struct {
		name, typ, target string
	}{
		{"api", "http", "https://example.com/health"},
		{"api", "http", "http://example.com"},
		{"api", "", "https://example.com"}, // empty type defaults to http
		{"db", "tcp", "db.example:5432"},
	}
	for _, c := range ok {
		if _, err := validateCheck(c.name, c.typ, c.target, 60, 0); err != nil {
			t.Errorf("validateCheck(%q,%q,%q) unexpected error: %v", c.name, c.typ, c.target, err)
		}
	}

	bad := []struct {
		desc, name, typ, target string
		interval, expect        int
	}{
		{"empty name", "", "http", "https://example.com", 60, 0},
		{"non-http scheme", "x", "http", "ftp://example.com", 60, 0},
		{"http without host", "x", "http", "https://", 60, 0},
		{"tcp without port", "x", "tcp", "db.example", 60, 0},
		{"tcp bad port", "x", "tcp", "db.example:99999", 60, 0},
		{"unknown type", "x", "icmp", "example.com", 60, 0},
		{"bad expect code", "x", "http", "https://example.com", 60, 42},
	}
	for _, c := range bad {
		if _, err := validateCheck(c.name, c.typ, c.target, c.interval, c.expect); err == nil {
			t.Errorf("validateCheck %s: expected error, got none", c.desc)
		}
	}

	// Interval is clamped, not rejected.
	got, err := validateCheck("x", "http", "https://example.com", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.IntervalS != minInterval {
		t.Errorf("interval 2 clamped to %d, want %d", got.IntervalS, minInterval)
	}
}
