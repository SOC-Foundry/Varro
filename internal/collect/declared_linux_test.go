//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"strings"
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

func TestDSNHosts(t *testing.T) {
	cases := []struct {
		dsn  string
		want []hostPort
	}{
		// real collector DSN: multi-host failover, shared port, creds + query stripped
		{"postgres://varro:s3cret@10.128.0.10,10.128.0.12:5432/varro?sslmode=verify-ca&target_session_attrs=read-write",
			[]hostPort{{"10.128.0.10", 5432}, {"10.128.0.12", 5432}}},
		// single host, default port
		{"postgresql://u:p@db.internal/app", []hostPort{{"db.internal", 5432}}},
		// per-host ports
		{"postgres://u@h1:5432,h2:5433/d", []hostPort{{"h1", 5432}, {"h2", 5433}}},
	}
	for _, c := range cases {
		got := dsnHosts(c.dsn, 5432)
		if len(got) != len(c.want) {
			t.Errorf("dsnHosts(%q) = %+v, want %+v", c.dsn, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("dsnHosts(%q)[%d] = %+v, want %+v", c.dsn, i, got[i], c.want[i])
			}
		}
		// never leak credentials into the host
		for _, hp := range got {
			if strings.Contains(hp.host, "s3cret") || strings.Contains(hp.host, "@") {
				t.Errorf("credential leaked into host: %q", hp.host)
			}
		}
	}
}

func TestSchemeKind(t *testing.T) {
	cases := []struct {
		uri, kind string
		port      int
	}{
		{"postgres://u@h:5432/d", "database", 5432},
		{"mysql://h/d", "database", 3306},
		{"redis://h:6379", "cache", 6379},
		{"rediss://h", "cache", 6379},
		{"amqp://h", "queue", 5672},
		{"kafka://h:9092", "queue", 9092},
		{"https://api.internal/v1", "service", 443},
		{"http://h", "service", 80},
	}
	for _, c := range cases {
		k, p := schemeKind(c.uri)
		if k != c.kind || p != c.port {
			t.Errorf("schemeKind(%q) = %q/%d, want %q/%d", c.uri, k, p, c.kind, c.port)
		}
	}
}

func TestConnURIScan(t *testing.T) {
	// Simulate a systemd Environment line with several connection strings.
	env := "FOO=bar REDIS_URL=redis://cache.int:6379/0 DB=postgres://u:p@db.int:5432/app AMQP=amqp://mq.int:5672 UP=https://api.int/health"
	got := map[string]string{} // host -> kind
	for _, uri := range connURIRe.FindAllString(env, -1) {
		kind, defPort := schemeKind(uri)
		for _, hp := range dsnHosts(uri, defPort) {
			got[hp.host] = kind
			if strings.Contains(hp.host, ":p@") || strings.Contains(hp.host, "p@") {
				t.Errorf("credential leaked into host: %q", hp.host)
			}
		}
	}
	want := map[string]string{"cache.int": "cache", "db.int": "database", "mq.int": "queue", "api.int": "service"}
	for h, k := range want {
		if got[h] != k {
			t.Errorf("host %q: got kind %q, want %q (all: %+v)", h, got[h], k, got)
		}
	}
}

func TestProxyDeps(t *testing.T) {
	// Point caddy glob at a temp dir with a Caddyfile by symlinking is awkward;
	// instead test the scan logic through a temp file read is internal — so just
	// exercise the regex + scan via a small inline harness mirroring proxyDeps.
	content := "example.com {\n  reverse_proxy backend.int:8080 backend2.int:8080\n  reverse_proxy /api/* http://api.int:9000\n}\n"
	var hosts []string
	for _, line := range strings.Split(content, "\n") {
		if !strings.Contains(line, "reverse_proxy") {
			continue
		}
		for _, m := range proxyHostPortRe.FindAllStringSubmatch(line, -1) {
			hosts = append(hosts, m[1]+":"+m[2])
		}
	}
	joined := strings.Join(hosts, ",")
	for _, want := range []string{"backend.int:8080", "backend2.int:8080", "api.int:9000"} {
		if !strings.Contains(joined, want) {
			t.Errorf("proxy scan missing %q; got %q", want, joined)
		}
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
