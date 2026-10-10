// Package server implements the Varro collector: telemetry ingest, query API,
// Prometheus exposition, and the embedded web dashboard.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
	"github.com/soc-foundry/varro/internal/store"
)

//go:embed web
var webFS embed.FS

//go:embed install.sh
var installScript string

//go:embed install.ps1
var installScriptPS string

// maxIngestBody bounds a single ingest request (an agent can batch up to an
// hour of buffered samples).
const maxIngestBody = 32 << 20

type Config struct {
	Listen    string
	Token     string        // master/admin token (enrolls into the default org; full API access)
	Retention time.Duration // how long samples are kept

	AgentInterval time.Duration // sampling interval pushed to agents
	AllowReenroll bool          // let an already-enrolled agent ID enroll again

	Rules            []model.AlertRule
	NotifyEventTypes map[string]bool // event types forwarded to notifiers
	WebhookURL       string
	SlackWebhookURL  string
	SMTP             SMTPConfig
	CFEmail          CFEmailConfig
	Gmail            GmailConfig
	Version          string

	VulnScan    bool     // match inventories against OSV.dev
	ThreatIntel bool     // match connection remotes against known-bad IP feeds
	ThreatFeeds []string // override the default IP indicator feeds
	HashFeeds   []string // override the default malware-hash feeds
	GeoIP       bool     // enrich external topology remotes with country/ASN (third-party lookups)

	Google       GoogleConfig    // Google sign-in; empty ClientID = open (lab) mode
	AdminEmails  map[string]bool // emails promoted to instance admin at sign-in
	MetricsToken string          // if set, /metrics requires this bearer token

	// Agent auto-upgrade: agents differing from AgentDesiredVersion download
	// that release from ReleaseRepo and replace themselves. Empty disables.
	AgentDesiredVersion string
	ReleaseRepo         string

	Backup BackupConfig
}

type Server struct {
	cfg       Config
	store     *store.Store
	log       *slog.Logger
	ips       *ipIndex
	listeners *listenerIndex
	rdns      *rdnsCache
	ti        *threatIntel
	det       *detector
	geo       *geoCache // nil unless GeoIP enabled
}

func New(cfg Config, st *store.Store, log *slog.Logger) *Server {
	s := &Server{cfg: cfg, store: st, log: log,
		ips: newIPIndex(), listeners: newListenerIndex(), rdns: newRDNSCache(), det: newDetector()}
	if cfg.ThreatIntel {
		s.ti = newThreatIntel(cfg.ThreatFeeds, cfg.HashFeeds)
	}
	if cfg.GeoIP {
		s.geo = newGeoCache("")
	}
	return s
}

// Run serves HTTP until the context is cancelled, pruning old samples in the
// background.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/ingest", s.handleIngest)
	mux.HandleFunc("POST /api/v1/enroll", s.handleEnroll)
	mux.HandleFunc("GET /api/v1/agent/config", s.handleAgentConfig)
	mux.HandleFunc("GET /api/v1/agent/actions", s.handleAgentActions)
	mux.HandleFunc("POST /api/v1/actions/{id}/ack", s.handleActionAck)
	mux.HandleFunc("POST /api/v1/endpoints/{id}/actions", s.handleIssueAction)
	mux.HandleFunc("GET /api/v1/endpoints/{id}/actions", s.handleListActions)
	mux.HandleFunc("GET /api/v1/endpoints", s.handleEndpoints)
	mux.HandleFunc("GET /api/v1/endpoints/{id}/latest", s.handleLatest)
	mux.HandleFunc("GET /api/v1/endpoints/{id}/history", s.handleHistory)
	mux.HandleFunc("GET /api/v1/endpoints/{id}/events", s.handleEndpointEvents)
	mux.HandleFunc("GET /api/v1/endpoints/{id}/inventory", s.handleInventory)
	mux.HandleFunc("GET /api/v1/endpoints/{id}/vulns", s.handleEndpointVulns)
	mux.HandleFunc("DELETE /api/v1/endpoints/{id}/token", s.handleRevokeToken)
	mux.HandleFunc("DELETE /api/v1/endpoints/{id}", s.handleEndpointRemove)
	mux.HandleFunc("DELETE /api/v1/orgs/{id}/members/{email}", s.handleOrgRemoveMember)
	mux.HandleFunc("GET /api/v1/events", s.handleEvents)
	mux.HandleFunc("GET /api/v1/alerts", s.handleAlerts)
	mux.HandleFunc("GET /api/v1/topology", s.handleTopology)
	mux.HandleFunc("DELETE /api/v1/orgs/{id}/edges", s.handleTopologyReset)
	mux.HandleFunc("GET /api/v1/me", s.handleMe)
	mux.HandleFunc("GET /api/v1/tokens", s.handleListUserTokens)
	mux.HandleFunc("POST /api/v1/tokens", s.handleCreateUserToken)
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", s.handleRevokeUserToken)
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/audit", s.handleAudit)
	mux.HandleFunc("GET /api/v1/orgs", s.handleOrgsList)
	mux.HandleFunc("POST /api/v1/orgs", s.handleOrgCreate)
	mux.HandleFunc("PUT /api/v1/orgs/{id}", s.handleOrgUpdate)
	mux.HandleFunc("DELETE /api/v1/orgs/{id}", s.handleOrgDelete)
	mux.HandleFunc("PUT /api/v1/users/{email}/admin", s.handleUserAdmin)
	mux.HandleFunc("PUT /api/v1/orgs/{id}/fim", s.handleOrgFIM)
	mux.HandleFunc("GET /api/v1/orgs/{id}/fim", s.handleOrgFIMGet)
	mux.HandleFunc("POST /api/v1/orgs/{id}/tokens", s.handleOrgToken)
	mux.HandleFunc("GET /api/v1/orgs/{id}/tokens", s.handleOrgTokens)
	mux.HandleFunc("POST /api/v1/orgs/{id}/members", s.handleOrgInvite)
	mux.HandleFunc("GET /api/v1/orgs/{id}/members", s.handleOrgMembers)
	mux.HandleFunc("GET /download/{asset}", s.handleDownload)
	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /install.sh", s.handleInstallScript)
	mux.HandleFunc("GET /install.ps1", s.handleInstallScriptPS)

	webRoot, err := fs.Sub(webFS, "web")
	if err != nil {
		return err
	}
	mux.Handle("GET /", http.FileServerFS(webRoot))

	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go s.pruneLoop(ctx)
	go s.alertLoop(ctx)
	if s.cfg.VulnScan {
		go s.vulnScanLoop(ctx)
	}
	if s.ti != nil {
		go s.threatRefreshLoop(ctx)
	}
	if s.backupEnabled() {
		go s.backupLoop(ctx)
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	s.log.Info("collector listening", "addr", s.cfg.Listen, "retention", s.cfg.Retention)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) pruneLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := s.store.Prune(ctx, s.cfg.Retention)
			if err != nil {
				s.log.Error("prune failed", "error", err)
			} else if n > 0 {
				s.log.Info("pruned old samples", "rows", n)
			}
			if err := s.store.PruneSessions(ctx); err != nil {
				s.log.Error("session prune failed", "error", err)
			}
			// Keep audit history longer than telemetry — 1 year.
			if err := s.store.PruneAudit(ctx, 365*24*time.Hour); err != nil {
				s.log.Error("audit prune failed", "error", err)
			}
		}
	}
}

// bearer extracts the Authorization bearer token, or "".
func bearer(r *http.Request) string {
	got, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return got
}

// masterAuthorized checks the shared enrollment token.
func (s *Server) masterAuthorized(r *http.Request) bool {
	return subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.cfg.Token)) == 1
}

// validAgentID constrains agent IDs to a safe charset. Besides defense in
// depth against injection wherever IDs are rendered, it keeps IDs usable in
// URLs and logs. Real IDs are machine-ids, DMI UUIDs, or hostnames — all
// within this set.
func validAgentID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == ':' || c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// agentAuthorized validates a per-agent token (X-Varro-Agent + bearer) and
// returns the org the agent enrolled into. The master token is also accepted
// ("lab mode") so agents can be pointed at a collector without enrollment;
// those report into the default org.
func (s *Server) agentAuthorized(r *http.Request) (agentID, orgID string, ok bool) {
	agentID = r.Header.Get("X-Varro-Agent")
	if agentID != "" {
		stored, org, err := s.store.AgentToken(r.Context(), agentID)
		if err == nil && stored != "" &&
			subtle.ConstantTimeCompare([]byte(hashToken(bearer(r))), []byte(stored)) == 1 {
			return agentID, org, true
		}
	}
	if s.masterAuthorized(r) {
		return agentID, model.DefaultOrg, true
	}
	return "", "", false
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	agentID, orgID, ok := s.agentAuthorized(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var snaps []*model.Snapshot
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxIngestBody))
	if err := dec.Decode(&snaps); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	// An agent authenticated with its own token may only report as itself.
	if agentID != "" {
		for _, snap := range snaps {
			if snap != nil && snap.AgentID != agentID {
				http.Error(w, "snapshot agent_id does not match authenticated agent", http.StatusForbidden)
				return
			}
		}
	}
	if err := s.store.Insert(r.Context(), snaps, orgID); err != nil {
		s.log.Error("ingest insert failed", "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	for _, snap := range snaps {
		if snap == nil {
			continue
		}
		if len(snap.Events) > 0 {
			s.notifyEvents(snap.Hostname, snap.Events)
		}
		s.correlateEdges(r, orgID, snap)
		s.checkThreats(r.Context(), orgID, snap)
		s.detect(r.Context(), orgID, snap)
	}
	writeJSON(w, map[string]int{"accepted": len(snaps)})
}

// handleEnroll exchanges an enrollment token (per-org, or the master token
// for the default org) for a per-agent token. The org the enrollment token
// belongs to becomes the agent's org.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var orgID string
	switch {
	case s.masterAuthorized(r):
		orgID = model.DefaultOrg
	default:
		org, err := s.store.OrgForTokenHash(r.Context(), hashToken(bearer(r)))
		if err != nil {
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		if org == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		orgID = org
	}

	var req struct {
		AgentID  string `json:"agent_id"`
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.AgentID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !validAgentID(req.AgentID) {
		http.Error(w, "invalid agent_id: allowed characters are letters, digits, and .:_-", http.StatusBadRequest)
		return
	}
	existing, _, err := s.store.AgentToken(r.Context(), req.AgentID)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if existing != "" && !s.cfg.AllowReenroll {
		http.Error(w, "agent already enrolled", http.StatusConflict)
		return
	}

	token, err := randomToken()
	if err != nil {
		http.Error(w, "entropy error", http.StatusInternalServerError)
		return
	}
	if err := s.store.SetAgentToken(r.Context(), req.AgentID, hashToken(token), orgID); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	s.log.Info("agent enrolled", "agent_id", req.AgentID, "hostname", req.Hostname, "org", orgID)
	writeJSON(w, map[string]string{"token": token, "org_id": orgID})
}

func (s *Server) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	_, orgID, ok := s.agentAuthorized(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	resp := map[string]any{
		"interval_seconds": int(s.cfg.AgentInterval / time.Second),
	}
	if v := s.cfg.AgentDesiredVersion; v != "" && v != "dev" {
		resp["desired_version"] = v
		resp["repo"] = s.cfg.ReleaseRepo
	}
	if paths, err := s.store.OrgFIMPaths(r.Context(), orgID); err == nil && len(paths) > 0 {
		resp["fim_paths"] = paths
	}
	writeJSON(w, resp)
}

// handleOrgFIM sets the org's file-integrity watchlist (org admins and up);
// agents receive it on their next config poll.
func (s *Server) handleOrgFIM(w http.ResponseWriter, r *http.Request) {
	org, err := s.store.OrgByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !s.orgAdminAuthorized(r, org.ID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request: need {\"paths\": [...]}", http.StatusBadRequest)
		return
	}
	var paths []string
	for _, p := range req.Paths {
		if p = strings.TrimSpace(p); p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) > 100 {
		http.Error(w, "too many watch paths (max 100)", http.StatusBadRequest)
		return
	}
	if err := s.store.SetOrgFIMPaths(r.Context(), org.ID, paths); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.Info("org FIM watchlist updated", "org", org.ID, "paths", len(paths))
	s.audit(r, "fim.update", org.ID, fmt.Sprintf("set %d watch path(s)", len(paths)))
	writeJSON(w, map[string]any{"org_id": org.ID, "paths": paths})
}

// handleRevokeToken revokes an agent's token. Permitted for admins of the
// endpoint's org and up — cutting off your own org's machine is org-level
// administration.
func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	org, err := s.store.EndpointOrg(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if org == "" {
		// Unknown endpoint: fall back to instance-level auth so the response
		// doesn't reveal endpoint existence to other tenants.
		if !s.adminAuthorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	} else if !s.orgAdminAuthorized(r, org) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	existed, err := s.store.DeleteAgentToken(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if !existed {
		http.Error(w, "no token for that agent", http.StatusNotFound)
		return
	}
	s.log.Info("agent token revoked", "agent_id", r.PathValue("id"))
	s.audit(r, "endpoint.revoke", org, "revoked token for "+r.PathValue("id"))
	writeJSON(w, map[string]bool{"revoked": true})
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	id, ok := s.endpointInScope(w, r, scope)
	if !ok {
		return
	}
	inv, ts, err := s.store.Inventory(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if inv == nil {
		http.Error(w, "no inventory reported yet", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{
		"collected_at": ts,
		"kernel":       inv.Kernel,
		"manager":      inv.Manager,
		"package_count": len(inv.Packages),
		"packages":     inv.Packages,
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	s.writeEvents(w, r, "", scope)
}

func (s *Server) handleEndpointEvents(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	id, ok := s.endpointInScope(w, r, scope)
	if !ok {
		return
	}
	s.writeEvents(w, r, id, scope)
}

func (s *Server) writeEvents(w http.ResponseWriter, r *http.Request, endpointID string, scope []string) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.store.Events(r.Context(), endpointID, scope, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []model.StoredEvent{}
	}
	writeJSON(w, events)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	alerts, err := s.store.Alerts(r.Context(), r.URL.Query().Get("state"), scope, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if alerts == nil {
		alerts = []model.Alert{}
	}
	writeJSON(w, alerts)
}

// handleHealth is an unauthenticated liveness probe exposing coarse,
// non-sensitive capability flags.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"status":        "ok",
		"version":       s.cfg.Version,
		"email_enabled": s.mailEnabled(),
		"auth_enabled":  s.AuthEnabled(),
		"threat_intel":  s.ti != nil,
	}
	if s.ti != nil {
		resp["threat_indicators"] = s.ti.count()
		resp["malware_hash_indicators"] = s.ti.hashCount()
	}
	writeJSON(w, resp)
}

func (s *Server) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	eps, err := s.store.Endpoints(r.Context(), scope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if eps == nil {
		eps = []model.EndpointSummary{}
	}
	writeJSON(w, eps)
}

// endpointInScope verifies the endpoint exists and belongs to an org the
// caller may read; it writes the error response itself when not.
func (s *Server) endpointInScope(w http.ResponseWriter, r *http.Request, scope []string) (string, bool) {
	id := r.PathValue("id")
	org, err := s.store.EndpointOrg(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return "", false
	}
	if org == "" {
		http.Error(w, "unknown endpoint", http.StatusNotFound)
		return "", false
	}
	if scope != nil {
		allowed := false
		for _, o := range scope {
			if o == org {
				allowed = true
				break
			}
		}
		if !allowed {
			// 404, not 403: don't confirm the endpoint exists to other tenants.
			http.Error(w, "unknown endpoint", http.StatusNotFound)
			return "", false
		}
	}
	return id, true
}

func (s *Server) handleLatest(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	id, ok := s.endpointInScope(w, r, scope)
	if !ok {
		return
	}
	snap, err := s.store.Latest(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if snap == nil {
		http.Error(w, "unknown endpoint", http.StatusNotFound)
		return
	}
	// Enrich connection remotes with reverse-DNS (cached, non-blocking).
	for i := range snap.Security.Connections {
		ip, _ := splitRemote(snap.Security.Connections[i].Remote)
		snap.Security.Connections[i].RemoteName = s.rdns.name(ip)
	}
	writeJSON(w, snap)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireReadScope(w, r)
	if !ok {
		return
	}
	id, ok := s.endpointInScope(w, r, scope)
	if !ok {
		return
	}
	minutes, _ := strconv.Atoi(r.URL.Query().Get("minutes"))
	if minutes <= 0 {
		minutes = 60
	}
	if minutes > 7*24*60 {
		minutes = 7 * 24 * 60
	}
	to := time.Now()
	from := to.Add(-time.Duration(minutes) * time.Minute)

	// Aim for ~360 points regardless of the window size.
	step := minutes * 60 / 360
	if step < 1 {
		step = 1
	}
	points, err := s.store.History(r.Context(), id, from, to, step)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if points == nil {
		points = []model.HistoryPoint{}
	}
	writeJSON(w, points)
}

// handleMetrics renders the latest sample of every endpoint in Prometheus
// text exposition format. If a metrics token is configured, scrapes must
// present it as a bearer token.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.cfg.MetricsToken != "" &&
		subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.cfg.MetricsToken)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	eps, err := s.store.Endpoints(r.Context(), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var b strings.Builder
	writeHelp := func(name, help, typ string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	writeHelp("varro_endpoint_up", "1 if the endpoint reported within the last minute.", "gauge")
	for _, ep := range eps {
		up := 0
		if ep.Online {
			up = 1
		}
		fmt.Fprintf(&b, "varro_endpoint_up{endpoint=%q,hostname=%q} %d\n", ep.ID, ep.Hostname, up)
	}

	writeHelp("varro_cpu_percent", "Total CPU utilization percent.", "gauge")
	writeHelp("varro_memory_used_bytes", "Memory in use in bytes.", "gauge")
	writeHelp("varro_memory_total_bytes", "Total physical memory in bytes.", "gauge")
	writeHelp("varro_network_receive_bytes_per_second", "Whole-host receive rate.", "gauge")
	writeHelp("varro_network_transmit_bytes_per_second", "Whole-host transmit rate.", "gauge")
	writeHelp("varro_disk_used_percent", "Filesystem usage percent per mountpoint.", "gauge")
	writeHelp("varro_load1", "1-minute load average.", "gauge")
	writeHelp("varro_processes_total", "Number of processes on the endpoint.", "gauge")
	writeHelp("varro_max_temp_celsius", "Hottest sensor reading.", "gauge")
	writeHelp("varro_disk_io_read_bytes_per_second", "Aggregate disk read rate.", "gauge")
	writeHelp("varro_disk_io_write_bytes_per_second", "Aggregate disk write rate.", "gauge")
	writeHelp("varro_posture_failures", "Failing CIS-lite posture checks.", "gauge")
	writeHelp("varro_vulnerabilities", "Known vulnerabilities in installed packages (OSV).", "gauge")
	writeHelp("varro_pending_updates", "Pending package updates.", "gauge")
	writeHelp("varro_reboot_required", "1 when a reboot is required to apply updates.", "gauge")
	writeHelp("varro_failed_services", "Services in a failed state.", "gauge")

	for _, ep := range eps {
		snap, err := s.store.Latest(r.Context(), ep.ID)
		if err != nil || snap == nil {
			continue
		}
		lbl := fmt.Sprintf("{endpoint=%q,hostname=%q}", ep.ID, ep.Hostname)
		fmt.Fprintf(&b, "varro_cpu_percent%s %.2f\n", lbl, snap.CPU.TotalPercent)
		fmt.Fprintf(&b, "varro_memory_used_bytes%s %d\n", lbl, snap.Memory.Used)
		fmt.Fprintf(&b, "varro_memory_total_bytes%s %d\n", lbl, snap.Memory.Total)
		fmt.Fprintf(&b, "varro_network_receive_bytes_per_second%s %.2f\n", lbl, snap.Network.RxRate)
		fmt.Fprintf(&b, "varro_network_transmit_bytes_per_second%s %.2f\n", lbl, snap.Network.TxRate)
		fmt.Fprintf(&b, "varro_load1%s %.2f\n", lbl, snap.CPU.Load1)
		fmt.Fprintf(&b, "varro_processes_total%s %d\n", lbl, snap.Host.NumProcs)
		var maxTemp, ioR, ioW float64
		for _, t := range snap.Hardware.Temps {
			if t.Celsius > maxTemp {
				maxTemp = t.Celsius
			}
		}
		for _, d := range snap.Hardware.DiskIO {
			ioR += d.ReadBps
			ioW += d.WriteBps
		}
		if maxTemp > 0 {
			fmt.Fprintf(&b, "varro_max_temp_celsius%s %.1f\n", lbl, maxTemp)
		}
		fmt.Fprintf(&b, "varro_disk_io_read_bytes_per_second%s %.2f\n", lbl, ioR)
		fmt.Fprintf(&b, "varro_disk_io_write_bytes_per_second%s %.2f\n", lbl, ioW)
		fails := 0
		for _, p := range snap.Posture {
			if p.Status == "fail" {
				fails++
			}
		}
		reboot := 0
		if snap.Health.RebootRequired {
			reboot = 1
		}
		fmt.Fprintf(&b, "varro_posture_failures%s %d\n", lbl, fails)
		fmt.Fprintf(&b, "varro_pending_updates%s %d\n", lbl, snap.Health.PendingUpdates)
		if n, err := s.store.VulnCount(r.Context(), ep.ID); err == nil {
			fmt.Fprintf(&b, "varro_vulnerabilities%s %d\n", lbl, n)
		}
		fmt.Fprintf(&b, "varro_reboot_required%s %d\n", lbl, reboot)
		fmt.Fprintf(&b, "varro_failed_services%s %d\n", lbl, len(snap.Health.FailedServices))
		for _, d := range snap.Disks {
			fmt.Fprintf(&b, "varro_disk_used_percent{endpoint=%q,hostname=%q,mountpoint=%q} %.2f\n",
				ep.ID, ep.Hostname, d.Mountpoint, d.UsedPercent)
		}
	}
	w.Write([]byte(b.String()))
}

// handleInstallScript serves the agent install one-liner script with this
// collector's URL baked in. Intentionally unauthenticated: it contains no
// secrets (the org token is supplied by the operator at install time).
func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Write([]byte(strings.ReplaceAll(installScript, "__VARRO_SERVER__",
		strings.TrimSuffix(s.cfg.Google.BaseURL, "/"))))
}

// handleOrgFIMGet returns the org's watchlist (org admins and up).
func (s *Server) handleOrgFIMGet(w http.ResponseWriter, r *http.Request) {
	org, err := s.store.OrgByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !s.orgAdminAuthorized(r, org.ID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	paths, err := s.store.OrgFIMPaths(r.Context(), org.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if paths == nil {
		paths = []string{}
	}
	writeJSON(w, map[string]any{"org_id": org.ID, "paths": paths})
}

// downloadAssets are the release binaries the dashboard offers for download.
var downloadAssets = map[string]bool{
	"varro-linux-amd64":       true,
	"varro-linux-arm64":       true,
	"varro-darwin-amd64":      true,
	"varro-darwin-arm64":      true,
	"varro-windows-amd64.exe": true,
	"checksums.txt":           true,
	"checksums.txt.sig":       true,
}

// handleDownload redirects to the latest release asset on GitHub, giving the
// dashboard first-party download URLs.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	asset := r.PathValue("asset")
	if !downloadAssets[asset] {
		http.Error(w, "unknown asset", http.StatusNotFound)
		return
	}
	http.Redirect(w, r,
		"https://github.com/"+s.cfg.ReleaseRepo+"/releases/latest/download/"+asset,
		http.StatusFound)
}

func (s *Server) handleInstallScriptPS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(strings.ReplaceAll(installScriptPS, "__VARRO_SERVER__",
		strings.TrimSuffix(s.cfg.Google.BaseURL, "/"))))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
