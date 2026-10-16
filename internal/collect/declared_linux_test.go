//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseMonitor(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pg_autoctl.cfg")
	os.WriteFile(p, []byte("[pg_autoctl]\nmonitor = postgres://autoctl_node@10.128.0.19:5432/pg_auto_failover?sslmode=require\nhostname = 10.128.0.10\n"), 0644)
	host, port := parseMonitor(p)
	if host != "10.128.0.19" || port != 5432 {
		t.Fatalf("parseMonitor = %q/%d, want 10.128.0.19/5432", host, port)
	}
}

func TestParsePrimaryConninfo(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "postgresql-auto-failover-standby.conf")
	os.WriteFile(p, []byte("# Settings by pg_auto_failover\nprimary_conninfo = 'application_name=pgautofailover_standby_2 host=10.128.0.10 port=5432 user=repl sslmode=require'\nprimary_slot_name = 'x'\n"), 0644)
	host, port := parsePrimaryConninfo(p)
	if host != "10.128.0.10" || port != 5432 {
		t.Fatalf("parsePrimaryConninfo = %q/%d, want 10.128.0.10/5432", host, port)
	}

	// Missing port defaults are handled by the caller; here just confirm host
	// parses when port is absent.
	p2 := filepath.Join(dir, "postgresql.conf")
	os.WriteFile(p2, []byte("primary_conninfo = 'host=db.internal user=r'\n"), 0644)
	h2, pt2 := parsePrimaryConninfo(p2)
	if h2 != "db.internal" || pt2 != 0 {
		t.Fatalf("parsePrimaryConninfo(no port) = %q/%d, want db.internal/0", h2, pt2)
	}
}

func TestPostgresDepsWalk(t *testing.T) {
	// Lay out a fake pgdata and point the walker at it.
	dir := t.TempDir()
	data := filepath.Join(dir, "15", "main")
	os.MkdirAll(filepath.Join(data, "base"), 0755) // pruned data subdir
	os.WriteFile(filepath.Join(data, "postgresql-auto-failover-standby.conf"),
		[]byte("primary_conninfo = 'host=10.0.0.5 port=5432 user=r'\n"), 0644)
	cfgdir := filepath.Join(dir, ".config", "pg_autoctl", data)
	os.MkdirAll(cfgdir, 0755)
	os.WriteFile(filepath.Join(cfgdir, "pg_autoctl.cfg"),
		[]byte("monitor = postgres://autoctl_node@10.0.0.9:5432/pg_auto_failover\n"), 0644)

	old := pgRoots
	pgRoots = []string{dir}
	defer func() { pgRoots = old }()

	deps := postgresDeps()
	var rep, mon bool
	for _, d := range deps {
		if d.Kind == "replication" && d.TargetHost == "10.0.0.5" && d.TargetPort == 5432 && d.Hard {
			rep = true
		}
		if d.Kind == "ha-monitor" && d.TargetHost == "10.0.0.9" && d.TargetPort == 5432 && d.Hard {
			mon = true
		}
	}
	if !rep || !mon {
		t.Fatalf("postgresDeps missing edges: rep=%v mon=%v, got %+v", rep, mon, deps)
	}
}
