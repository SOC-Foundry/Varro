package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// DefaultRules apply when no --rules file is given.
var DefaultRules = []model.AlertRule{
	{Name: "high-cpu", Metric: "cpu_pct", Op: ">", Threshold: 90, ForSeconds: 300},
	{Name: "high-memory", Metric: "mem_pct", Op: ">", Threshold: 95, ForSeconds: 300},
	{Name: "high-swap", Metric: "swap_pct", Op: ">", Threshold: 80, ForSeconds: 300},
	{Name: "disk-almost-full", Metric: "disk_pct", Op: ">", Threshold: 85, ForSeconds: 60},
	{Name: "overheating", Metric: "max_temp_c", Op: ">", Threshold: 90, ForSeconds: 120},
	{Name: "offline", Metric: "offline", ForSeconds: 90},
}

// Anomaly detection: compare the recent average of these metrics against a
// 7-day baseline; fire beyond 3 sigma, resolve under 2 sigma. minStd floors
// the deviation so near-constant metrics don't alert on trivial wiggles.
var anomalyMetrics = []struct {
	metric string
	minStd float64
}{
	{"cpu_pct", 2.0},
	{"rx_rate", 10 * 1024},
	{"tx_rate", 10 * 1024},
}

const (
	anomalyBaseline = 7 * 24 * time.Hour
	anomalyRecent   = 10 * time.Minute
	anomalyMinN     = 180 // baseline must have at least this many samples

	ruleEvalEvery    = 15 * time.Second
	anomalyEvalEvery = 5 * time.Minute
)

func LoadRules(path string) ([]model.AlertRule, error) {
	if path == "" {
		return DefaultRules, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []model.AlertRule
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, r := range rules {
		if r.Name == "" || r.Metric == "" {
			return nil, fmt.Errorf("rule missing name or metric: %+v", r)
		}
	}
	return rules, nil
}

// alertLoop drives threshold and anomaly evaluation.
func (s *Server) alertLoop(ctx context.Context) {
	rules := time.NewTicker(ruleEvalEvery)
	anomalies := time.NewTicker(anomalyEvalEvery)
	defer rules.Stop()
	defer anomalies.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-rules.C:
			s.evaluateRules(ctx)
		case <-anomalies.C:
			s.evaluateAnomalies(ctx)
		}
	}
}

func (s *Server) evaluateRules(ctx context.Context) {
	eps, err := s.store.Endpoints(ctx, nil)
	if err != nil {
		s.log.Error("alert eval: list endpoints", "error", err)
		return
	}
	s.resolveOrphanedAlerts(ctx)
	for _, rule := range s.cfg.Rules {
		for _, ep := range eps {
			if rule.Metric == "offline" {
				silent := time.Since(ep.LastSeen)
				s.setAlertState(ctx, rule.Name, ep,
					silent > time.Duration(rule.ForSeconds)*time.Second,
					silent.Seconds(),
					fmt.Sprintf("%s has not reported for %s", ep.Hostname, silent.Truncate(time.Second)))
				continue
			}

			// Metric rules only make sense for endpoints currently reporting;
			// the window query naturally returns no rows for silent ones.
			window := time.Duration(rule.ForSeconds) * time.Second
			if window < 30*time.Second {
				window = 30 * time.Second
			}
			avg, n, err := s.store.WindowAvg(ctx, ep.ID, rule.Metric, window)
			if err != nil {
				s.log.Error("alert eval: window avg", "rule", rule.Name, "error", err)
				continue
			}
			breaching := n >= 2
			if breaching {
				switch rule.Op {
				case "<":
					breaching = avg < rule.Threshold
				default:
					breaching = avg > rule.Threshold
				}
			}
			s.setAlertState(ctx, rule.Name, ep, breaching, avg,
				fmt.Sprintf("%s: %s averaged %.1f over %s (threshold %s %.1f)",
					ep.Hostname, rule.Metric, avg, window, opOrDefault(rule.Op), rule.Threshold))
		}
	}
}

// resolveOrphanedAlerts closes firing alerts whose rule no longer exists
// (e.g. after the server restarted with a different rules file); otherwise
// they would stay open forever since nothing evaluates them.
func (s *Server) resolveOrphanedAlerts(ctx context.Context) {
	known := map[string]bool{}
	for _, r := range s.cfg.Rules {
		known[r.Name] = true
	}
	for _, am := range anomalyMetrics {
		known["anomaly-"+am.metric] = true
	}
	firing, err := s.store.Alerts(ctx, model.AlertFiring, nil, 1000)
	if err != nil {
		return
	}
	for _, a := range firing {
		if !known[a.Rule] {
			if err := s.store.ResolveAlert(ctx, a.ID); err == nil {
				s.log.Info("resolved orphaned alert for removed rule", "rule", a.Rule, "endpoint", a.Hostname)
			}
		}
	}
}

func opOrDefault(op string) string {
	if op == "" {
		return ">"
	}
	return op
}

func (s *Server) evaluateAnomalies(ctx context.Context) {
	eps, err := s.store.Endpoints(ctx, nil)
	if err != nil {
		return
	}
	now := time.Now()
	for _, ep := range eps {
		if !ep.Online {
			continue
		}
		for _, am := range anomalyMetrics {
			mean, std, n, err := s.store.Baseline(ctx, ep.ID, am.metric,
				now.Add(-anomalyBaseline), now.Add(-anomalyRecent))
			if err != nil || n < anomalyMinN {
				continue
			}
			if std < am.minStd {
				std = am.minStd
			}
			current, cn, err := s.store.WindowAvg(ctx, ep.ID, am.metric, anomalyRecent)
			if err != nil || cn < 5 {
				continue
			}
			z := (current - mean) / std
			if z < 0 {
				z = -z
			}
			ruleName := "anomaly-" + am.metric
			open, _ := s.store.OpenAlert(ctx, ruleName, ep.ID)
			// Hysteresis: fire above 3 sigma, resolve below 2.
			if open == 0 && z > 3 {
				s.setAlertState(ctx, ruleName, ep, true, current,
					fmt.Sprintf("%s: %s is %.1f, %.1f sigma from its 7-day norm of %.1f",
						ep.Hostname, am.metric, current, z, mean))
			} else if open != 0 && z < 2 {
				s.setAlertState(ctx, ruleName, ep, false, current, "")
			}
		}
	}
}

// setAlertState reconciles desired vs stored alert state, notifying on
// transitions only.
func (s *Server) setAlertState(ctx context.Context, rule string, ep model.EndpointSummary, breaching bool, value float64, message string) {
	openID, err := s.store.OpenAlert(ctx, rule, ep.ID)
	if err != nil {
		s.log.Error("alert state lookup", "rule", rule, "error", err)
		return
	}
	switch {
	case breaching && openID == 0:
		alert := model.Alert{
			OrgID:      ep.OrgID,
			Rule:       rule,
			EndpointID: ep.ID,
			Hostname:   ep.Hostname,
			Message:    message,
			Value:      value,
			StartedAt:  time.Now().UTC(),
		}
		if _, err := s.store.FireAlert(ctx, alert); err != nil {
			s.log.Error("fire alert", "rule", rule, "error", err)
			return
		}
		s.log.Warn("ALERT firing", "rule", rule, "endpoint", ep.Hostname, "message", message)
		s.notify("firing", rule, ep.Hostname, message)
	case !breaching && openID != 0:
		if err := s.store.ResolveAlert(ctx, openID); err != nil {
			s.log.Error("resolve alert", "rule", rule, "error", err)
			return
		}
		msg := fmt.Sprintf("%s: %s resolved", ep.Hostname, rule)
		s.log.Info("alert resolved", "rule", rule, "endpoint", ep.Hostname)
		s.notify("resolved", rule, ep.Hostname, msg)
	}
}

// notifyEvents forwards security events of configured types the moment they
// are ingested.
func (s *Server) notifyEvents(hostname string, events []model.Event) {
	for _, ev := range events {
		if s.cfg.NotifyEventTypes[ev.Type] {
			s.notify("event", ev.Type, hostname, ev.Message)
		}
	}
}

// ---- notification transports ----

func (s *Server) notify(state, rule, hostname, message string) {
	text := fmt.Sprintf("[varro] %s · %s · %s — %s", strings.ToUpper(state), rule, hostname, message)
	if s.cfg.WebhookURL != "" {
		go s.postJSON(s.cfg.WebhookURL, map[string]string{
			"state": state, "rule": rule, "hostname": hostname, "message": message,
		})
	}
	if s.cfg.SlackWebhookURL != "" {
		go s.postJSON(s.cfg.SlackWebhookURL, map[string]string{"text": text})
	}
	if s.mailEnabled() && len(s.cfg.SMTP.To) > 0 {
		go s.sendMail(text)
	}
}

func (s *Server) postJSON(url string, payload any) {
	body, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.log.Error("webhook notify failed", "url", url, "error", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		s.log.Error("webhook notify rejected", "url", url, "status", resp.Status)
	}
}

type SMTPConfig struct {
	Host string
	Port int
	User string
	Pass string
	From string
	To   []string
}

func (s *Server) sendMail(text string) {
	s.sendMailTo(s.cfg.SMTP.To, text, text)
}

// sendMailTo delivers one message via Cloudflare Email Service when
// configured, falling back to the SMTP relay.
func (s *Server) sendMailTo(to []string, subject, body string) {
	if len(to) == 0 {
		return
	}
	if s.cfEmailEnabled() {
		s.sendViaCloudflare(to, subject, body)
		return
	}
	c := s.cfg.SMTP
	if c.Host == "" {
		return
	}
	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	msg := []byte("From: " + c.From + "\r\n" +
		"To: " + strings.Join(to, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n\r\n" +
		body + "\r\n")
	var auth smtp.Auth
	if c.User != "" {
		auth = smtp.PlainAuth("", c.User, c.Pass, c.Host)
	}
	if err := smtp.SendMail(addr, auth, c.From, to, msg); err != nil {
		s.log.Error("email send failed", "error", err)
	}
}
