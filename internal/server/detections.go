package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// builtinDetections describes the hardcoded behavioral rules for the management
// UI. Their logic lives in detect.go; operators can disable or re-severity them
// per org via detection_settings.
var builtinDetections = []model.BuiltinRuleInfo{
	{Name: "reverse_shell", Severity: "HIGH", MITRE: "T1059", Desc: "Shell/network tool with a live outbound connection"},
	{Name: "shell_listener", Severity: "HIGH", MITRE: "T1059", Desc: "Shell/network tool bound to a listening port (backdoor)"},
	{Name: "crypto_miner", Severity: "HIGH", MITRE: "T1496", Desc: "Known miner binary, or pegged CPU to a mining-pool port"},
	{Name: "recon_tool", Severity: "MEDIUM", MITRE: "T1046", Desc: "Network reconnaissance tool executed or connecting out"},
	{Name: "exec_storm", Severity: "MEDIUM", MITRE: "T1059", Desc: "Abnormal burst of distinct process execs in one interval"},
}

// ---- per-org rule cache (refreshed lazily; detect() runs per snapshot) ----

type detOrgRules struct {
	rules     []model.DetectionRule
	settings  map[string]model.DetectionSetting
	playbooks []model.Playbook
	at        time.Time
}

type detCache struct {
	mu    sync.Mutex
	byOrg map[string]*detOrgRules
}

func newDetCache() *detCache { return &detCache{byOrg: map[string]*detOrgRules{}} }

func (s *Server) orgDetections(ctx context.Context, orgID string) *detOrgRules {
	s.detc.mu.Lock()
	defer s.detc.mu.Unlock()
	if od := s.detc.byOrg[orgID]; od != nil && time.Since(od.at) < 30*time.Second {
		return od
	}
	rules, err := s.store.DetectionRules(ctx, orgID)
	if err != nil {
		if od := s.detc.byOrg[orgID]; od != nil {
			return od
		}
		return &detOrgRules{settings: map[string]model.DetectionSetting{}, at: time.Now()}
	}
	settings, _ := s.store.DetectionSettings(ctx, orgID)
	if settings == nil {
		settings = map[string]model.DetectionSetting{}
	}
	playbooks, _ := s.store.Playbooks(ctx, orgID)
	od := &detOrgRules{rules: rules, settings: settings, playbooks: playbooks, at: time.Now()}
	s.detc.byOrg[orgID] = od
	return od
}

func (s *Server) invalidateDetections(orgID string) {
	s.detc.mu.Lock()
	delete(s.detc.byOrg, orgID)
	s.detc.mu.Unlock()
}

// fireDetection records + notifies a detection (shared by built-in and custom).
func (s *Server) fireDetection(ctx context.Context, orgID string, snap *model.Snapshot, rule, severity, mitre, key, msg string) {
	if !s.det.should(snap.AgentID, rule, key) {
		return
	}
	full := fmt.Sprintf("[%s] %s", severity, rule)
	if mitre != "" {
		full += " (ATT&CK " + mitre + ")"
	}
	full += ": " + msg
	s.store.InsertServerEvent(ctx, orgID, snap.AgentID, model.EventDetection, full)
	s.log.Warn("behavioral detection", "rule", rule, "severity", severity, "endpoint", snap.Hostname, "detail", msg)
	s.notifyEvents(orgID, snap.Hostname, []model.Event{{Type: model.EventDetection, Message: full}})
	s.siemForward(orgID, snap.Hostname, "detection", severity, mitre, full)
	if _, err := s.store.AttachSignal(ctx, orgID, snap.AgentID, snap.Hostname, "detection", severity, "Detection: "+rule, full); err != nil {
		s.log.Error("incident attach (detection)", "rule", rule, "error", err)
	}
	s.runPlaybooks(ctx, orgID, snap, rule, severity)
}

// evaluateCustomDetections runs the org's custom/Sigma rules against a snapshot.
func (s *Server) evaluateCustomDetections(ctx context.Context, orgID string, snap *model.Snapshot, od *detOrgRules) {
	for _, r := range od.rules {
		if !r.Enabled || len(r.Conditions) == 0 {
			continue
		}
		for _, doc := range detDocs(r.Stream, snap) {
			if matchRule(r, doc) {
				s.fireDetection(ctx, orgID, snap, "custom:"+r.Name, r.Severity, r.MITRE,
					r.ID+"|"+detDocKey(doc),
					snap.Hostname+": custom rule \""+r.Name+"\" matched ("+detDocDesc(r.Stream, doc)+")")
			}
		}
	}
}

// detDocs projects a snapshot's streams into field documents for matching.
func detDocs(stream string, snap *model.Snapshot) []map[string]string {
	var docs []map[string]string
	switch stream {
	case model.DetStreamProcess:
		for _, p := range snap.Processes {
			docs = append(docs, map[string]string{"image": p.Name, "command": p.Cmdline, "user": p.Username})
		}
		for _, e := range snap.Execs {
			docs = append(docs, map[string]string{"image": e.Comm, "command": e.Comm})
		}
	case model.DetStreamConnection:
		for _, c := range snap.Security.Connections {
			ip, port := splitRemote(c.Remote)
			docs = append(docs, map[string]string{"image": c.Process, "dest": ip, "port": itoa(port), "domain": c.Domain})
		}
		for _, c := range snap.Conns {
			docs = append(docs, map[string]string{"image": c.Comm, "dest": c.Dest, "port": itoa(int(c.Port))})
		}
	case model.DetStreamListener:
		for _, lp := range snap.Security.ListeningPorts {
			docs = append(docs, map[string]string{"image": lp.Process, "port": itoa(int(lp.Port)), "address": lp.Address})
		}
	}
	return docs
}

func detDocKey(doc map[string]string) string {
	cmd := doc["command"]
	if len(cmd) > 40 {
		cmd = cmd[:40]
	}
	return doc["image"] + "|" + doc["dest"] + "|" + doc["port"] + "|" + cmd
}

func detDocDesc(stream string, doc map[string]string) string {
	switch stream {
	case model.DetStreamConnection:
		return doc["image"] + " → " + doc["dest"] + ":" + doc["port"]
	case model.DetStreamListener:
		return doc["image"] + " listening :" + doc["port"]
	default:
		if doc["command"] != "" {
			return doc["command"]
		}
		return doc["image"]
	}
}

func matchRule(r model.DetectionRule, doc map[string]string) bool {
	if len(r.Conditions) == 0 {
		return false
	}
	for _, c := range r.Conditions {
		if !matchCond(c, doc[c.Field]) {
			return false
		}
	}
	return true
}

func matchCond(c model.DetCond, v string) bool {
	if v == "" {
		return false
	}
	lv := strings.ToLower(v)
	for _, want := range c.Values {
		lw := strings.ToLower(want)
		switch c.Op {
		case "contains":
			if strings.Contains(lv, lw) {
				return true
			}
		case "startswith":
			if strings.HasPrefix(lv, lw) {
				return true
			}
		case "endswith":
			if strings.HasSuffix(lv, lw) {
				return true
			}
		case "regex":
			if re, err := regexp.Compile(want); err == nil && re.MatchString(v) {
				return true
			}
		default: // equals
			if lv == lw {
				return true
			}
		}
	}
	return false
}

// ---- handlers (org-admin) ----

func (s *Server) detOrgOrDeny(w http.ResponseWriter, r *http.Request) (string, bool) {
	org, err := s.store.OrgByRef(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return "", false
	}
	if !s.orgAdminAuthorized(r, org.ID) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	return org.ID, true
}

func (s *Server) handleDetectionsList(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	settings, _ := s.store.DetectionSettings(r.Context(), orgID)
	builtins := make([]map[string]any, 0, len(builtinDetections))
	for _, b := range builtinDetections {
		enabled, sev := true, b.Severity
		if st, ok := settings[b.Name]; ok {
			enabled = st.Enabled
			if st.Severity != "" {
				sev = st.Severity
			}
		}
		builtins = append(builtins, map[string]any{
			"name": b.Name, "desc": b.Desc, "mitre": b.MITRE,
			"severity": sev, "default_severity": b.Severity, "enabled": enabled,
		})
	}
	custom, err := s.store.DetectionRules(r.Context(), orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if custom == nil {
		custom = []model.DetectionRule{}
	}
	writeJSON(w, map[string]any{"builtins": builtins, "custom": custom})
}

func (s *Server) handleDetectionCreate(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	var rule model.DetectionRule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&rule); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := validateDetectionRule(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rule.OrgID = orgID
	rule.Enabled = true
	rule.Source = "custom"
	created, err := s.store.CreateDetectionRule(r.Context(), rule)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.invalidateDetections(orgID)
	s.audit(r, "detection.create", orgID, created.Name)
	writeJSON(w, created)
}

func (s *Server) handleDetectionSigma(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	var req struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || strings.TrimSpace(req.YAML) == "" {
		http.Error(w, "need {\"yaml\": \"...\"}", http.StatusBadRequest)
		return
	}
	rule, warnings, err := ParseSigma(req.YAML)
	if err != nil {
		http.Error(w, "sigma: "+err.Error(), http.StatusBadRequest)
		return
	}
	rule.OrgID = orgID
	created, err := s.store.CreateDetectionRule(r.Context(), rule)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.invalidateDetections(orgID)
	s.audit(r, "detection.sigma", orgID, created.Name)
	writeJSON(w, map[string]any{"rule": created, "warnings": warnings})
}

func (s *Server) handleDetectionUpdate(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	changed, err := s.store.SetDetectionRuleEnabled(r.Context(), orgID, r.PathValue("ruleID"), req.Enabled)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !changed {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.invalidateDetections(orgID)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleDetectionDelete(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	removed, err := s.store.DeleteDetectionRule(r.Context(), orgID, r.PathValue("ruleID"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.invalidateDetections(orgID)
	s.audit(r, "detection.delete", orgID, r.PathValue("ruleID"))
	writeJSON(w, map[string]bool{"removed": true})
}

func (s *Server) handleDetectionBuiltin(w http.ResponseWriter, r *http.Request) {
	orgID, ok := s.detOrgOrDeny(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	known := false
	for _, b := range builtinDetections {
		if b.Name == name {
			known = true
		}
	}
	if !known {
		http.Error(w, "unknown built-in rule", http.StatusNotFound)
		return
	}
	var req struct {
		Enabled  bool   `json:"enabled"`
		Severity string `json:"severity"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Severity != "" && !validSeverity(req.Severity) {
		http.Error(w, "bad severity", http.StatusBadRequest)
		return
	}
	if err := s.store.SetDetectionSetting(r.Context(), orgID, model.DetectionSetting{
		RuleName: name, Enabled: req.Enabled, Severity: req.Severity,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.invalidateDetections(orgID)
	s.audit(r, "detection.builtin", orgID, name)
	writeJSON(w, map[string]bool{"ok": true})
}

func validSeverity(s string) bool {
	switch s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return true
	}
	return false
}

func validateDetectionRule(r *model.DetectionRule) error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	switch r.Stream {
	case model.DetStreamProcess, model.DetStreamConnection, model.DetStreamListener:
	default:
		return fmt.Errorf("stream must be process, connection, or listener")
	}
	if r.Severity == "" {
		r.Severity = "MEDIUM"
	}
	if !validSeverity(r.Severity) {
		return fmt.Errorf("severity must be CRITICAL, HIGH, MEDIUM, or LOW")
	}
	var conds []model.DetCond
	for _, c := range r.Conditions {
		c.Field = strings.TrimSpace(c.Field)
		if c.Field == "" || len(c.Values) == 0 {
			continue
		}
		switch c.Op {
		case "equals", "contains", "startswith", "endswith", "regex":
		case "":
			c.Op = "contains"
		default:
			return fmt.Errorf("op must be equals, contains, startswith, endswith, or regex")
		}
		if c.Op == "regex" {
			for _, v := range c.Values {
				if _, err := regexp.Compile(v); err != nil {
					return fmt.Errorf("invalid regex %q: %v", v, err)
				}
			}
		}
		conds = append(conds, c)
	}
	if len(conds) == 0 {
		return fmt.Errorf("at least one condition (field + values) is required")
	}
	r.Conditions = conds
	return nil
}
