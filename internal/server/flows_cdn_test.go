package server

import "testing"

func TestIsCDN(t *testing.T) {
	cases := []struct {
		dest, geo string
		want      bool
	}{
		{"main.vscode-cdn.net", "ZA · AS8075 Microsoft Corporation", true}, // "cdn" in hostname
		{"assets.ramp.com", "CA · AS13335 Cloudflare, Inc.", true},         // Cloudflare by name
		{"x.example.com", "US · AS54113 Fastly", true},                     // Fastly by name
		{"y.example.com", "DE · AS20940 Akamai International", true},       // Akamai by ASN
		{"api.anthropic.com", "US · AS399358 Anthropic, PBC", false},       // real geo, keep it
		{"ssl.gstatic.com", "US · AS15169 Google LLC", false},              // hyperscaler, not de-geo'd
		{"compute.googleapis.com", "US · AS15169 Google LLC", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := isCDN(c.dest, c.geo); got != c.want {
			t.Errorf("isCDN(%q, %q) = %v, want %v", c.dest, c.geo, got, c.want)
		}
	}
}
