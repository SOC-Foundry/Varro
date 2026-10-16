//go:build linux

package collect

import (
	"bufio"
	"context"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/soc-foundry/varro/internal/model"
)

// CollectDeclaredDeps reads configured ("declared") dependencies from the host:
// systemd service ordering/requirements (intra-host) and Postgres / pg_auto_failover
// connection config (cross-host). Best-effort — any failure yields fewer entries,
// never an error, so the worst case is an empty overlay.
func CollectDeclaredDeps(ctx context.Context) []model.DeclaredDep {
	var out []model.DeclaredDep
	out = append(out, systemdDeps(ctx)...)
	out = append(out, postgresDeps()...)
	out = append(out, proxyDeps()...)
	return out
}

// proxyHostPortRe matches "host:port" or "scheme://host:port" upstream targets.
var proxyHostPortRe = regexp.MustCompile(`(?:[a-z]+://)?([a-zA-Z0-9][a-zA-Z0-9.\-]*):(\d{2,5})`)

// proxyDeps parses reverse-proxy upstreams from caddy and nginx config into
// declared "service" dependencies (the web server depends on its upstreams).
// Best-effort; unresolved/own-host targets are dropped server-side.
func proxyDeps() []model.DeclaredDep {
	var deps []model.DeclaredDep
	seen := map[string]bool{}
	add := func(from, host string, port int) {
		if host == "" || port == 0 || len(deps) >= 200 {
			return
		}
		k := from + "|" + host + ":" + strconv.Itoa(port)
		if seen[k] {
			return
		}
		seen[k] = true
		deps = append(deps, model.DeclaredDep{Kind: model.DepKindService, From: from, TargetHost: host, TargetPort: port})
	}
	scan := func(from, content string, triggers []string) {
		for _, line := range strings.Split(content, "\n") {
			l := strings.TrimSpace(line)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			hit := false
			for _, t := range triggers {
				if strings.Contains(l, t) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
			for _, m := range proxyHostPortRe.FindAllStringSubmatch(l, -1) {
				port, _ := strconv.Atoi(m[2])
				add(from, m[1], port)
			}
		}
	}
	glob := func(pats ...string) []string {
		var fs []string
		for _, p := range pats {
			if m, err := filepath.Glob(p); err == nil {
				fs = append(fs, m...)
			}
		}
		return fs
	}
	// Caddy: reverse_proxy / "to" upstream directives.
	for _, f := range glob("/etc/caddy/Caddyfile", "/etc/caddy/*.caddy", "/etc/caddy/conf.d/*") {
		if b, err := readCappedFile(f, 512*1024); err == nil {
			scan("caddy", string(b), []string{"reverse_proxy", "to "})
		}
	}
	// Nginx: *_pass directives point at upstreams (bare "server" lines are skipped
	// to avoid confusing listen addresses with upstream targets).
	for _, f := range glob("/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*") {
		if b, err := readCappedFile(f, 512*1024); err == nil {
			scan("nginx", string(b), []string{"proxy_pass", "fastcgi_pass", "uwsgi_pass", "grpc_pass"})
		}
	}
	return deps
}

// systemdDeps returns service→service dependencies of the running services. Hard =
// Requires/BindsTo; soft = After ordering. Only .service targets are kept (so the
// result is service-to-service, not .target/.mount/.socket noise).
func systemdDeps(ctx context.Context) []model.DeclaredDep {
	units := runningServices(ctx)
	if len(units) == 0 {
		return nil
	}
	args := append([]string{"show", "--no-pager", "-p", "Id", "-p", "Requires", "-p", "BindsTo", "-p", "After", "-p", "Environment"}, units...)
	out, err := exec.CommandContext(ctx, "systemctl", args...).Output()
	if err != nil {
		return nil
	}
	var deps []model.DeclaredDep
	seen := map[string]bool{}
	id, requires, bindsto, after, env := "", "", "", "", ""
	flush := func() {
		if id == "" {
			return
		}
		add := func(list string, hard bool) {
			for _, t := range strings.Fields(list) {
				if !strings.HasSuffix(t, ".service") || t == id {
					continue
				}
				k := id + "|" + t
				if seen[k] || len(deps) >= 200 {
					continue
				}
				seen[k] = true
				deps = append(deps, model.DeclaredDep{Kind: model.DepKindSystemd, From: id, Target: t, Hard: hard})
			}
		}
		add(requires, true)
		add(bindsto, true)
		add(after, false)
		// Connection-string URIs in the service's environment → cross-host deps
		// (host/port only; credentials are never extracted or stored). Covers
		// Postgres/MySQL/Mongo (database), Redis (cache), AMQP/Kafka (queue), and
		// http(s) upstreams (service).
		for _, uri := range connURIRe.FindAllString(env, -1) {
			kind, defPort := schemeKind(uri)
			for _, hp := range dsnHosts(uri, defPort) {
				k := id + "|" + kind + "|" + hp.host
				if seen[k] || len(deps) >= 200 {
					continue
				}
				seen[k] = true
				deps = append(deps, model.DeclaredDep{Kind: kind, From: id, TargetHost: hp.host, TargetPort: hp.port, Hard: kind == model.DepKindDatabase})
			}
		}
		id, requires, bindsto, after, env = "", "", "", "", ""
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" { // blank line separates unit blocks
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "Id":
			flush() // new block started without a blank separator
			id = v
		case "Requires":
			requires = v
		case "BindsTo":
			bindsto = v
		case "After":
			after = v
		case "Environment":
			env = v
		}
	}
	flush()
	return deps
}

// connURIRe matches connection-string URIs for the service schemes we map to
// declared dependencies.
var connURIRe = regexp.MustCompile(`(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|kafka|https?)://\S+`)

// schemeKind maps a connection URI to its declared-dependency kind and default
// port (port is display-only; resolution to a fleet host is by host).
func schemeKind(uri string) (string, int) {
	scheme := strings.ToLower(uri)
	if i := strings.Index(scheme, "://"); i >= 0 {
		scheme = scheme[:i]
	}
	switch scheme {
	case "postgres", "postgresql":
		return model.DepKindDatabase, 5432
	case "mysql":
		return model.DepKindDatabase, 3306
	case "mongodb", "mongodb+srv":
		return model.DepKindDatabase, 27017
	case "redis", "rediss":
		return model.DepKindCache, 6379
	case "amqp", "amqps":
		return model.DepKindQueue, 5672
	case "kafka":
		return model.DepKindQueue, 9092
	case "http":
		return model.DepKindService, 80
	case "https":
		return model.DepKindService, 443
	}
	return model.DepKindService, 0
}

type hostPort struct {
	host string
	port int
}

// dsnHosts extracts the target host(s) and port from a connection URI, ignoring
// credentials. Handles multi-host authorities (failover DSNs) like "h1,h2:5432"
// and per-host ports "h1:5432,h2:5433". defPort fills hosts that specify no port.
func dsnHosts(dsn string, defPort int) []hostPort {
	rest := dsn
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	auth := rest
	if i := strings.IndexAny(auth, "/?"); i >= 0 {
		auth = auth[:i] // drop path + query
	}
	if i := strings.LastIndex(auth, "@"); i >= 0 {
		auth = auth[i+1:] // drop credentials
	}
	if auth == "" {
		return nil
	}
	var out []hostPort
	global := 0
	for _, p := range strings.Split(auth, ",") {
		h, pt := splitHostPortNum(p)
		if h == "" {
			continue
		}
		out = append(out, hostPort{h, pt})
		if pt != 0 {
			global = pt
		}
	}
	for i := range out {
		if out[i].port == 0 {
			out[i].port = global
		}
		if out[i].port == 0 {
			out[i].port = defPort
		}
	}
	return out
}

// splitHostPortNum splits "host:port" only when the suffix is numeric (so an IPv6
// address without a port isn't truncated); otherwise the whole string is the host.
func splitHostPortNum(s string) (string, int) {
	s = strings.TrimSpace(s)
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, 0
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return s, 0
	}
	return s[:i], port
}

func runningServices(ctx context.Context) []string {
	out, err := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service",
		"--state=running", "--no-legend", "--plain", "--no-pager").Output()
	if err != nil {
		return nil
	}
	var units []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) > 0 && strings.HasSuffix(f[0], ".service") {
			units = append(units, f[0])
			if len(units) >= 300 {
				break
			}
		}
	}
	return units
}

var (
	pgHostRe = regexp.MustCompile(`host=(\S+)`)
	pgPortRe = regexp.MustCompile(`port=(\d+)`)
)

// pgRoots are the directories searched for Postgres / pg_auto_failover config.
var pgRoots = []string{"/var/lib/postgresql", "/etc/postgresql", "/var/lib/pgsql"}

// pgPruneDirs are Postgres data subdirectories we never descend into (large,
// never config) so the bounded walk stays cheap.
var pgPruneDirs = map[string]bool{
	"base": true, "pg_wal": true, "pg_xact": true, "global": true, "pg_stat": true,
	"pg_stat_tmp": true, "pg_logical": true, "pg_replslot": true, "pg_tblspc": true,
	"pg_multixact": true, "pg_subtrans": true, "pg_notify": true, "pg_serial": true,
	"pg_snapshots": true, "pg_commit_ts": true, "pg_dynshmem": true, "log": true,
	"archive": true, "archived_wal": true,
}

// postgresDeps parses the pg_auto_failover monitor URI and the standby's
// primary_conninfo from config files under the Postgres roots.
func postgresDeps() []model.DeclaredDep {
	var deps []model.DeclaredDep
	seen := map[string]bool{}
	addEdge := func(kind, from, host string, port int) {
		if host == "" {
			return
		}
		k := kind + "|" + host
		if seen[k] {
			return
		}
		seen[k] = true
		if port == 0 {
			port = 5432
		}
		deps = append(deps, model.DeclaredDep{Kind: kind, From: from, TargetHost: host, TargetPort: port, Hard: true})
	}

	visited := 0
	for _, root := range pgRoots {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || visited > 20000 {
				if visited > 20000 {
					return filepath.SkipAll
				}
				return nil
			}
			visited++
			if d.IsDir() {
				if pgPruneDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			switch {
			case name == "pg_autoctl.cfg":
				if host, port := parseMonitor(p); host != "" {
					addEdge(model.DepKindHAMonitor, "pg_autoctl", host, port)
				}
			case name == "postgresql-auto-failover-standby.conf" ||
				name == "postgresql.auto.conf" || name == "postgresql.conf":
				if host, port := parsePrimaryConninfo(p); host != "" {
					addEdge(model.DepKindReplication, "postgres", host, port)
				}
			}
			return nil
		})
	}
	return deps
}

// parseMonitor reads the `monitor = postgres://…@host:port/…` line from a
// pg_autoctl.cfg and returns the monitor host and port.
func parseMonitor(path string) (string, int) {
	b, err := readCappedFile(path, 256*1024)
	if err != nil {
		return "", 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "monitor") {
			continue
		}
		_, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(v))
		if err != nil || u.Hostname() == "" {
			continue
		}
		port, _ := strconv.Atoi(u.Port())
		return u.Hostname(), port
	}
	return "", 0
}

// parsePrimaryConninfo extracts host/port from a `primary_conninfo = '…'` line.
func parsePrimaryConninfo(path string) (string, int) {
	b, err := readCappedFile(path, 256*1024)
	if err != nil {
		return "", 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "primary_conninfo") {
			continue
		}
		m := pgHostRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		host := strings.Trim(m[1], "'\"")
		port := 0
		if pm := pgPortRe.FindStringSubmatch(line); pm != nil {
			port, _ = strconv.Atoi(pm[1])
		}
		return host, port
	}
	return "", 0
}

func readCappedFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}
