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

	Google       GoogleConfig    // Google sign-in; empty ClientID = open (lab) mode
	AdminEmails  map[string]bool // emails promoted to instance admin at sign-in
	MetricsToken string          // if set, /metrics requires this bearer token

	// Agent auto-upgrade: agents differing from AgentDesiredVersion download
	// that release from ReleaseRepo and replace themselves. Empty disables.
	AgentDesiredVersion string
	ReleaseRepo         string
}

type Server struct {
	cfg   Config
	store *store.Store
	log   *slog.Logger
}

func New(cfg Config, st *store.Store, log *slog.Logger) *Server {
	return &Server{cfg: cfg, store: st, log: log}
}

// Run serves HTTP until the context is cancelled, pruning old samples in the
// background.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/ingest", s.handleIngest)
	mux.HandleFunc("POST /api/v1/enroll", s.handleEnroll)
	mux.HandleFunc("GET /api/v1/agent/config", s.handleAgentConfig)
	mux.HandleFunc("GET /api/v1/endpoints", s.handleEndpoints)
	mux.HandleFunc("GET /api/v1/endpoints/{id}/latest", s.handleLatest)
	mux.HandleFunc("GET /api/v1/endpoints/{id}/history", s.handleHistory)
	mux.HandleFunc("GET /api/v1/endpoints/{id}/events", s.handleEndpointEvents)
	mux.HandleFunc("GET /api/v1/endpoints/{id}/inventory", s.handleInventory)
	mux.HandleFunc("DELETE /api/v1/endpoints/{id}/token", s.handleRevokeToken)
	mux.HandleFunc("DELETE /api/v1/endpoints/{id}", s.handleEndpointRemove)
	mux.HandleFunc("DELETE /api/v1/orgs/{id}/members/{email}", s.handleOrgRemoveMember)
	mux.HandleFunc("GET /api/v1/events", s.handleEvents)
	mux.HandleFunc("GET /api/v1/alerts", s.handleAlerts)
	mux.HandleFunc("GET /api/v1/me", s.handleMe)
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/orgs", s.handleOrgsList)
	mux.HandleFunc("POST /api/v1/orgs", s.handleOrgCreate)
	mux.HandleFunc("PUT /api/v1/orgs/{id}", s.handleOrgUpdate)
	mux.HandleFunc("DELETE /api/v1/orgs/{id}", s.handleOrgDelete)
	mux.HandleFunc("PUT /api/v1/users/{email}/admin", s.handleUserAdmin)
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
		if snap != nil && len(snap.Events) > 0 {
			s.notifyEvents(snap.Hostname, snap.Events)
		}
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
	if _, _, ok := s.agentAuthorized(r); !ok {
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
	writeJSON(w, resp)
}

// handleRevokeToken revokes an agent's token (admin action, master token).
func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if !s.masterAuthorized(r) {
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
	writeJSON(w, map[string]any{
		"status":        "ok",
		"version":       s.cfg.Version,
		"email_enabled": s.mailEnabled(),
		"auth_enabled":  s.AuthEnabled(),
	})
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
