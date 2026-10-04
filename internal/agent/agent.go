// Package agent runs the collect-and-ship loop on an endpoint.
//
// On first run the agent enrolls with the collector using the shared
// enrollment token and receives a per-agent token, which is persisted in the
// state directory and used for all subsequent requests. Samples that cannot
// be shipped are spooled to disk so a restart loses nothing.
package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/collect"
	"github.com/soc-foundry/varro/internal/model"
)

// maxBuffer bounds the backlog kept while the collector is unreachable. At a
// 10s interval this is about one hour of samples.
const maxBuffer = 360

const (
	tokenFile = "agent-token"
	spoolFile = "spool.jsonl"

	configFetchEvery = 5 * time.Minute
	enrollRetryEvery = 10 * time.Second
)

type Config struct {
	ServerURL   string        // base URL of the collector
	EnrollToken string        // shared enrollment token (used only to obtain a per-agent token)
	Interval    time.Duration // initial sampling interval; the server may override it
	StateDir    string        // where the per-agent token and spool live
}

type Agent struct {
	cfg        Config
	collector  *collect.Collector
	client     *http.Client
	buffer     []*model.Snapshot
	agentToken string
	interval   time.Duration
	log        *slog.Logger
}

// Version is the agent build version, injected by the main package.
var Version = "dev"

func New(ctx context.Context, cfg Config, log *slog.Logger) (*Agent, error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	cleanupOldBinary()
	legacyID, _ := collect.LegacyHostID(ctx)
	agentID, err := resolveAgentID(cfg.StateDir, legacyID)
	if err != nil {
		return nil, err
	}
	c := collect.New(agentID, Version)
	return &Agent{
		cfg:       cfg,
		collector: c,
		client:    &http.Client{Timeout: 15 * time.Second},
		interval:  cfg.Interval,
		log:       log,
	}, nil
}

// Run enrolls (if needed), then samples on the configured interval and ships
// to the collector until the context is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.loadToken()
	if a.agentToken == "" {
		if err := a.enrollLoop(ctx); err != nil {
			return err
		}
	}

	a.loadSpool()
	rc := a.fetchConfig(ctx)
	if rc.IntervalSeconds > 0 {
		a.interval = time.Duration(rc.IntervalSeconds) * time.Second
	}
	a.collector.SetFIMPaths(rc.FIMPaths)
	a.maybeUpgrade(ctx, rc)

	a.log.Info("agent started",
		"agent_id", a.collector.AgentID(),
		"version", Version,
		"server", a.cfg.ServerURL,
		"interval", a.interval,
		"state_dir", a.cfg.StateDir,
		"spooled", len(a.buffer))

	// Prime CPU/network/process/security state so the first shipped sample
	// has real deltas and the event baselines are established silently.
	if _, err := a.collector.Sample(ctx); err != nil {
		return fmt.Errorf("initial sample: %w", err)
	}

	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	lastConfigFetch := time.Now()
	for {
		select {
		case <-ctx.Done():
			a.writeSpool()
			return nil
		case <-ticker.C:
		}

		snap, err := a.collector.Sample(ctx)
		if err != nil {
			a.log.Error("sample failed", "error", err)
			continue
		}
		a.buffer = append(a.buffer, snap)
		if len(a.buffer) > maxBuffer {
			a.buffer = a.buffer[len(a.buffer)-maxBuffer:]
		}

		if err := a.ship(ctx); err != nil {
			a.log.Warn("ship failed, spooling", "error", err, "buffered", len(a.buffer))
			a.writeSpool()
		}

		if time.Since(lastConfigFetch) >= configFetchEvery {
			lastConfigFetch = time.Now()
			rc := a.fetchConfig(ctx)
			if newInterval := time.Duration(rc.IntervalSeconds) * time.Second; rc.IntervalSeconds > 0 && newInterval != a.interval {
				a.log.Info("server changed sampling interval", "from", a.interval, "to", newInterval)
				a.interval = newInterval
				ticker.Reset(a.interval)
			}
			a.collector.SetFIMPaths(rc.FIMPaths)
			a.maybeUpgrade(ctx, rc)
		}
	}
}

// ---- enrollment and tokens ----

func (a *Agent) tokenPath() string { return filepath.Join(a.cfg.StateDir, tokenFile) }
func (a *Agent) spoolPath() string { return filepath.Join(a.cfg.StateDir, spoolFile) }

func (a *Agent) loadToken() {
	if b, err := os.ReadFile(a.tokenPath()); err == nil {
		a.agentToken = strings.TrimSpace(string(b))
	}
}

func (a *Agent) enrollLoop(ctx context.Context) error {
	if a.cfg.EnrollToken == "" {
		return fmt.Errorf("no stored agent token and no enrollment token provided")
	}
	for {
		err := a.enroll(ctx)
		if err == nil {
			return nil
		}
		a.log.Warn("enrollment failed, retrying", "error", err, "retry_in", enrollRetryEvery)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(enrollRetryEvery):
		}
	}
}

func (a *Agent) enroll(ctx context.Context) error {
	hostname, _ := os.Hostname()
	body, _ := json.Marshal(map[string]string{
		"agent_id": a.collector.AgentID(),
		"hostname": hostname,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.cfg.ServerURL+"/api/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.cfg.EnrollToken)

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("agent already enrolled; revoke its token on the server (varro revoke) or run the server with --allow-reenroll")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enroll returned %s", resp.Status)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.Token == "" {
		return fmt.Errorf("enroll returned an empty token")
	}
	a.agentToken = out.Token
	if err := os.WriteFile(a.tokenPath(), []byte(out.Token+"\n"), 0o600); err != nil {
		return fmt.Errorf("persist agent token: %w", err)
	}
	a.log.Info("enrolled with collector", "agent_id", a.collector.AgentID())
	return nil
}

func (a *Agent) authedRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	var r *bytes.Reader
	if body != nil {
		r = bytes.NewReader(body)
	} else {
		r = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.cfg.ServerURL+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.agentToken)
	req.Header.Set("X-Varro-Agent", a.collector.AgentID())
	return req, nil
}

// ---- shipping and spool ----

// ship sends the whole buffer in one batch and clears it (and the spool) on
// success. A 401 means the token was revoked server-side; one re-enrollment
// attempt is made so a wiped server database heals automatically.
func (a *Agent) ship(ctx context.Context) error {
	body, err := json.Marshal(a.buffer)
	if err != nil {
		return err
	}
	req, err := a.authedRequest(ctx, http.MethodPost, "/api/v1/ingest", body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		a.log.Warn("agent token rejected, attempting re-enrollment")
		if enrollErr := a.enroll(ctx); enrollErr != nil {
			return fmt.Errorf("token rejected and re-enroll failed: %w", enrollErr)
		}
		return fmt.Errorf("token rejected; re-enrolled, will retry next tick")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("collector returned %s", resp.Status)
	}
	a.buffer = a.buffer[:0]
	os.Remove(a.spoolPath())
	a.collector.InventoryDelivered()
	return nil
}

// writeSpool persists the current buffer as JSON lines, replacing any
// previous spool.
func (a *Agent) writeSpool() {
	if len(a.buffer) == 0 {
		return
	}
	f, err := os.OpenFile(a.spoolPath(), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		a.log.Error("open spool failed", "error", err)
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, snap := range a.buffer {
		if err := enc.Encode(snap); err != nil {
			a.log.Error("write spool failed", "error", err)
			return
		}
	}
	w.Flush()
}

// loadSpool restores any samples a previous run could not deliver.
func (a *Agent) loadSpool() {
	f, err := os.Open(a.spoolPath())
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		var snap model.Snapshot
		if err := json.Unmarshal(sc.Bytes(), &snap); err == nil {
			a.buffer = append(a.buffer, &snap)
		}
	}
	if len(a.buffer) > maxBuffer {
		a.buffer = a.buffer[len(a.buffer)-maxBuffer:]
	}
	if len(a.buffer) > 0 {
		a.log.Info("restored spooled samples", "count", len(a.buffer))
	}
}

// ---- server-pushed config ----

// fetchConfig asks the collector for agent settings (sampling interval,
// desired agent version). Returns a zero value when unavailable.
func (a *Agent) fetchConfig(ctx context.Context) remoteConfig {
	req, err := a.authedRequest(ctx, http.MethodGet, "/api/v1/agent/config", nil)
	if err != nil {
		return remoteConfig{}
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return remoteConfig{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return remoteConfig{}
	}
	var out remoteConfig
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return remoteConfig{}
	}
	return out
}
