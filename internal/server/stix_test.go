package server

import (
	"strings"
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestParseSTIXIndicators(t *testing.T) {
	bundle := `{
	  "type": "bundle",
	  "objects": [
	    {"type":"indicator","pattern_type":"stix","pattern":"[ipv4-addr:value = '203.0.113.5']"},
	    {"type":"indicator","pattern_type":"stix","pattern":"[domain-name:value = 'Evil.Example.' OR domain-name:value = 'bad.example']"},
	    {"type":"indicator","pattern_type":"stix","pattern":"[url:value = 'http://phish.example/login']"},
	    {"type":"indicator","pattern_type":"stix","pattern":"[file:hashes.'SHA-256' = 'AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899']"},
	    {"type":"ipv4-addr","value":"198.51.100.7"},
	    {"type":"domain-name","value":"raw.example"},
	    {"type":"file","hashes":{"SHA-256":"1111111111111111111111111111111111111111111111111111111111111111","MD5":"deadbeef"}},
	    {"type":"indicator","pattern":"[ipv4-addr:value = 'not-an-ip']"},
	    {"type":"identity","name":"ignored"}
	  ]
	}`
	iocs := parseSTIXIndicators([]byte(bundle), "feedX", 100)

	got := map[string]string{} // value -> type
	for _, i := range iocs {
		got[i.Value] = i.Type
		if i.Source != "feedX" || i.AddedAt != 100 {
			t.Errorf("ioc %+v missing source/added_at", i)
		}
	}
	want := map[string]string{
		"203.0.113.5":   model.IOCTypeIP,
		"198.51.100.7":  model.IOCTypeIP,
		"evil.example":  model.IOCTypeDomain, // lowercased, trailing dot stripped
		"bad.example":   model.IOCTypeDomain,
		"phish.example": model.IOCTypeDomain, // host extracted from URL
		"raw.example":   model.IOCTypeDomain,
		"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899": model.IOCTypeHash, // lowercased
		"1111111111111111111111111111111111111111111111111111111111111111": model.IOCTypeHash,
	}
	for v, ty := range want {
		if got[v] != ty {
			t.Errorf("missing/wrong IOC %q: got type %q, want %q", v, got[v], ty)
		}
	}
	if _, bad := got["not-an-ip"]; bad {
		t.Error("invalid IP should have been rejected")
	}
	if len(iocs) != len(want) {
		t.Errorf("got %d IOCs, want %d: %+v", len(iocs), len(want), got)
	}
}

func TestStripUserinfo(t *testing.T) {
	cases := map[string]string{
		"https://user:pass@taxii.example/collections/1/objects/": "https://taxii.example/collections/1/objects/",
		"https://taxii.example/feed.json":                        "https://taxii.example/feed.json",
		"https://tokenuser@host/path?x=1":                        "https://host/path?x=1",
		"not a url":                                              "not a url",
	}
	for in, want := range cases {
		if got := stripUserinfo(in); got != want {
			t.Errorf("stripUserinfo(%q) = %q, want %q", in, got, want)
		}
		if strings.Contains(stripUserinfo(in), "pass") || strings.Contains(stripUserinfo(in), "@") && strings.Contains(in, ":pass@") {
			t.Errorf("credential survived stripUserinfo(%q) = %q", in, stripUserinfo(in))
		}
	}
}

func TestParseSTIXEmpty(t *testing.T) {
	if iocs := parseSTIXIndicators([]byte(`not json`), "x", 1); iocs != nil {
		t.Errorf("garbage input should yield nil, got %+v", iocs)
	}
	if iocs := parseSTIXIndicators([]byte(`{"objects":[]}`), "x", 1); iocs != nil {
		t.Errorf("empty objects should yield nil, got %+v", iocs)
	}
}

func TestNormalizeIOC(t *testing.T) {
	cases := []struct {
		inT, inV, wantT, wantV string
		ok                     bool
	}{
		{"ip", " 1.2.3.4 ", "ip", "1.2.3.4", true},
		{"IP", "::1", "ip", "::1", true},
		{"ip", "999.1.1.1", "", "", false},
		{"domain", "Evil.Example.", "domain", "evil.example", true},
		{"domain", "nodot", "", "", false},
		{"hash", "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899", "hash", "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", true},
		{"hash", "tooshort", "", "", false},
		{"ja3", "AABBCCDDEEFF00112233445566778899", "ja3", "aabbccddeeff00112233445566778899", true}, // 32-hex MD5
		{"ja3", "deadbeef", "", "", false},                                                          // too short
		{"bogus", "x", "", "", false},
	}
	for _, c := range cases {
		gt, gv, ok := normalizeIOC(c.inT, c.inV)
		if ok != c.ok || gt != c.wantT || gv != c.wantV {
			t.Errorf("normalizeIOC(%q,%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.inT, c.inV, gt, gv, ok, c.wantT, c.wantV, c.ok)
		}
	}
}
