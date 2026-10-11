//go:build linux

package collect

import "testing"

func TestSplitPeerAddr(t *testing.T) {
	cases := []struct {
		in, ip, port string
	}{
		{"93.184.216.34:443", "93.184.216.34", "443"},
		{"[2606:2800:220:1:248:1893:25c8:1946]:443", "2606:2800:220:1:248:1893:25c8:1946", "443"},
		{"[::1]:80", "::1", "80"},
		{"noport", "", ""},
	}
	for _, c := range cases {
		ip, port := splitPeerAddr(c.in)
		if ip != c.ip || port != c.port {
			t.Errorf("splitPeerAddr(%q) = (%q,%q), want (%q,%q)", c.in, ip, port, c.ip, c.port)
		}
	}
}

func TestParseUint(t *testing.T) {
	for in, want := range map[string]uint64{"1234": 1234, "0": 0, "": 0, "12ab": 12, "abc": 0} {
		if got := parseUint(in); got != want {
			t.Errorf("parseUint(%q) = %d, want %d", in, got, want)
		}
	}
}
