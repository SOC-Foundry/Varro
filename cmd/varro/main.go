// Command varro is the Varro endpoint-telemetry suite in a single binary:
//
//	varro agent      run the telemetry agent on this machine
//	varro server     run the central collector (API + dashboard + /metrics)
//	varro endpoints  list endpoints known to a collector
//	varro status     print the latest snapshot for an endpoint
//	varro top        live htop-style view of an endpoint
//	varro alerts     list firing (or all) alerts
//	varro events     show the security/change event feed
//	varro revoke     revoke an agent's token
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/soc-foundry/varro/internal/agent"
	"github.com/soc-foundry/varro/internal/cli"
	"github.com/soc-foundry/varro/internal/server"
	"github.com/soc-foundry/varro/internal/store"
)

// version is stamped via -ldflags "-X main.version=..." on release builds.
var version = "0.20.1"

func main() {
	agent.Version = version

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "agent":
		err = runAgent(ctx, os.Args[2:])
	case "server":
		err = runServer(ctx, os.Args[2:])
	case "endpoints":
		err = cli.Endpoints(ctx, os.Args[2:])
	case "status":
		err = cli.Status(ctx, os.Args[2:])
	case "top":
		err = cli.Top(ctx, os.Args[2:])
	case "alerts":
		err = cli.Alerts(ctx, os.Args[2:])
	case "events":
		err = cli.Events(ctx, os.Args[2:])
	case "audit":
		err = cli.Audit(ctx, os.Args[2:])
	case "revoke":
		err = cli.Revoke(ctx, os.Args[2:])
	case "orgs":
		err = cli.Orgs(ctx, os.Args[2:])
	case "org-create":
		err = cli.OrgCreate(ctx, os.Args[2:])
	case "onboard":
		err = cli.Onboard(ctx, os.Args[2:])
	case "org-token":
		err = cli.OrgToken(ctx, os.Args[2:])
	case "org-invite":
		err = cli.OrgInvite(ctx, os.Args[2:])
	case "org-remove-member":
		err = cli.OrgRemoveMember(ctx, os.Args[2:])
	case "org-delete":
		err = cli.OrgDelete(ctx, os.Args[2:])
	case "user-admin":
		err = cli.UserAdmin(ctx, os.Args[2:])
	case "endpoint-remove":
		err = cli.EndpointRemove(ctx, os.Args[2:])
	case "inventory":
		err = cli.Inventory(ctx, os.Args[2:])
	case "vulns":
		err = cli.Vulns(ctx, os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("varro", version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "varro: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "varro:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`Varro — endpoint telemetry

Usage:
  varro agent     --server URL --token TOKEN [--interval 10s] [--state-dir DIR]
  varro server    --token TOKEN [--listen :9477] [--db varro.db] [--retention 72h]
                  [--agent-interval 10s] [--allow-reenroll] [--rules rules.json]
                  [--webhook-url URL] [--slack-webhook-url URL]
                  [--smtp-host H --smtp-port 587 --smtp-from A --smtp-to A,B]
                  [--notify-events autostart_change,nic_new,listen_new]
  varro endpoints [--server URL]
  varro status    [endpoint] [--server URL]
  varro top       [endpoint] [--server URL] [--interval 2s]
  varro alerts    [--server URL] [--all] [-n 50]
  varro events    [endpoint] [--server URL] [-n 50]
  varro audit     [--server URL] [--token ADMIN] [-n 100]
  varro inventory [endpoint] [--server URL] [--grep NAME]
  varro vulns     [endpoint] [--server URL] [--grep NAME]
  varro revoke    <endpoint> [--server URL] [--token TOKEN]
  varro onboard <org> <admin-email> [--domain d.com]        one-shot customer setup
  varro orgs                              [--token ADMIN]   list orgs
  varro org-create <name> [--domain d.com] [--token ADMIN]  create an org
  varro org-token  <org> [--name LABEL]   [--token ADMIN]   mint agent enrollment token
  varro org-invite <org> <email>          [--token ADMIN]   grant a Google user access
  varro org-remove-member <org> <email>   [--token ADMIN]   drop a user from an org
  varro org-delete <org>                  [--token ADMIN]   delete an empty org
  varro user-admin <email> grant|revoke   [--token ADMIN]   instance-admin status
  varro endpoint-remove <endpoint>        [--token ADMIN]   delete an endpoint + its data

The agent and the query commands default --server to $VARRO_SERVER; tokens
default to $VARRO_TOKEN (and SMTP password to $VARRO_SMTP_PASS). The agent's
--token is only used once, to enroll: it then receives its own per-agent token,
stored in --state-dir.
`)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func defaultStateDir() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "Varro")
		}
	}
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "varro")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "state", "varro")
	}
	return ".varro-state"
}

func runAgent(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	serverURL := fs.String("server", envOr("VARRO_SERVER", ""), "collector base URL")
	token := fs.String("token", envOr("VARRO_TOKEN", ""), "enrollment token")
	interval := fs.Duration("interval", 10*time.Second, "sampling interval (server config may override)")
	stateDir := fs.String("state-dir", defaultStateDir(), "directory for agent token and offline spool")
	fs.Parse(args)
	if *serverURL == "" {
		return fmt.Errorf("agent requires --server (or VARRO_SERVER)")
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	a, err := agent.New(ctx, agent.Config{
		ServerURL:   *serverURL,
		EnrollToken: *token,
		Interval:    *interval,
		StateDir:    *stateDir,
	}, log)
	if err != nil {
		return err
	}
	if isWindowsService() {
		return runAsService(ctx, "varro-agent", a.Run)
	}
	return a.Run(ctx)
}

func runServer(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", ":9477", "listen address")
	token := fs.String("token", envOr("VARRO_TOKEN", ""), "enrollment/admin token")
	dbPath := fs.String("db", "varro.db", "SQLite database path")
	retention := fs.Duration("retention", 72*time.Hour, "how long to keep samples and events")
	agentInterval := fs.Duration("agent-interval", 10*time.Second, "sampling interval pushed to agents")
	allowReenroll := fs.Bool("allow-reenroll", false, "allow an enrolled agent ID to enroll again")
	rulesPath := fs.String("rules", "", "JSON file of alert rules (default: built-in rules)")
	webhookURL := fs.String("webhook-url", envOr("VARRO_WEBHOOK_URL", ""), "generic JSON webhook for notifications")
	slackURL := fs.String("slack-webhook-url", envOr("VARRO_SLACK_WEBHOOK_URL", ""), "Slack incoming-webhook URL")
	notifyEvents := fs.String("notify-events", "threat_match,malware_match,autostart_change,nic_new,listen_new,suid_change,identity_change",
		"comma-separated event types forwarded to notifiers (empty to disable)")
	smtpHost := fs.String("smtp-host", "", "SMTP host for email notifications")
	smtpPort := fs.Int("smtp-port", 587, "SMTP port")
	smtpUser := fs.String("smtp-user", "", "SMTP username")
	smtpPass := fs.String("smtp-pass", os.Getenv("VARRO_SMTP_PASS"), "SMTP password")
	smtpFrom := fs.String("smtp-from", "", "email From address")
	smtpTo := fs.String("smtp-to", "", "comma-separated alert recipient addresses")
	cfAccountID := fs.String("cf-email-account-id", os.Getenv("VARRO_CF_ACCOUNT_ID"),
		"Cloudflare account ID for Email Service sending (preferred over SMTP)")
	cfEmailToken := fs.String("cf-email-token", os.Getenv("VARRO_CF_EMAIL_TOKEN"),
		"Cloudflare API token with Email Sending permission")
	cfEmailFrom := fs.String("cf-email-from", os.Getenv("VARRO_CF_EMAIL_FROM"),
		"sender address at a domain onboarded to Cloudflare Email Sending")
	gmailSAKey := fs.String("gmail-sa-json", os.Getenv("VARRO_GMAIL_SA_JSON"),
		"path to a Google service-account key JSON for Gmail API sending (domain-wide delegation)")
	gmailSendAs := fs.String("gmail-send-as", os.Getenv("VARRO_GMAIL_SEND_AS"),
		"Workspace user to impersonate and send as via the Gmail API")
	googleClientID := fs.String("google-client-id", os.Getenv("VARRO_GOOGLE_CLIENT_ID"),
		"Google OAuth client ID; setting this turns on required sign-in")
	googleClientSecret := fs.String("google-client-secret", os.Getenv("VARRO_GOOGLE_CLIENT_SECRET"),
		"Google OAuth client secret")
	baseURL := fs.String("base-url", envOr("VARRO_BASE_URL", "http://localhost:9477"),
		"externally visible base URL (used for the OAuth redirect)")
	adminEmails := fs.String("admin-emails", os.Getenv("VARRO_ADMIN_EMAILS"),
		"comma-separated emails promoted to instance admin at sign-in (first user is always admin)")
	metricsToken := fs.String("metrics-token", os.Getenv("VARRO_METRICS_TOKEN"),
		"if set, /metrics requires this bearer token")
	vulnScan := fs.Bool("vuln-scan", true,
		"match package inventories against OSV.dev for known vulnerabilities")
	threatIntel := fs.Bool("threat-intel", true,
		"match connection remotes against known-malicious IP feeds (abuse.ch)")
	threatFeeds := fs.String("threat-feeds", "",
		"comma-separated IP indicator feed URLs (default: Feodo Tracker C2 list)")
	hashFeeds := fs.String("threat-hash-feeds", "",
		"comma-separated malware-hash feed URLs (default: MalwareBazaar recent sha256)")
	autoUpgrade := fs.Bool("agent-auto-upgrade", true,
		"push the desired agent version so agents self-upgrade from GitHub releases")
	desiredVersion := fs.String("agent-desired-version", "",
		"pin agents to a specific released version (default: this server's version)")
	releaseRepo := fs.String("release-repo", "SOC-Foundry/Varro",
		"GitHub repo agents download release binaries from")
	fs.Parse(args)
	if *token == "" {
		return fmt.Errorf("server requires --token (or VARRO_TOKEN)")
	}
	if *googleClientID != "" && *googleClientSecret == "" {
		return fmt.Errorf("--google-client-id requires --google-client-secret (or VARRO_GOOGLE_CLIENT_SECRET)")
	}

	admins := map[string]bool{}
	for _, e := range splitNonEmpty(*adminEmails) {
		admins[strings.ToLower(e)] = true
	}

	rules, err := server.LoadRules(*rulesPath)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}

	notifySet := map[string]bool{}
	for _, t := range strings.Split(*notifyEvents, ",") {
		if t = strings.TrimSpace(t); t != "" {
			notifySet[t] = true
		}
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv := server.New(server.Config{
		Listen:           *listen,
		Token:            *token,
		Retention:        *retention,
		AgentInterval:    *agentInterval,
		AllowReenroll:    *allowReenroll,
		Rules:            rules,
		NotifyEventTypes: notifySet,
		WebhookURL:       *webhookURL,
		SlackWebhookURL:  *slackURL,
		SMTP: server.SMTPConfig{
			Host: *smtpHost, Port: *smtpPort,
			User: *smtpUser, Pass: *smtpPass,
			From: *smtpFrom, To: splitNonEmpty(*smtpTo),
		},
		CFEmail: server.CFEmailConfig{
			AccountID: *cfAccountID,
			Token:     *cfEmailToken,
			From:      *cfEmailFrom,
		},
		Gmail: server.GmailConfig{
			SAKeyPath: *gmailSAKey,
			SendAs:    *gmailSendAs,
		},
		Version: version,
		Google: server.GoogleConfig{
			ClientID:     *googleClientID,
			ClientSecret: *googleClientSecret,
			BaseURL:      *baseURL,
		},
		AdminEmails:  admins,
		MetricsToken: *metricsToken,
		VulnScan:     *vulnScan,
		ThreatIntel:  *threatIntel,
		ThreatFeeds:  splitNonEmpty(*threatFeeds),
		HashFeeds:    splitNonEmpty(*hashFeeds),
		AgentDesiredVersion: func() string {
			if !*autoUpgrade {
				return ""
			}
			if *desiredVersion != "" {
				return *desiredVersion
			}
			return version
		}(),
		ReleaseRepo: *releaseRepo,
	}, st, log)
	return srv.Run(ctx)
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
