package server

import "time"

// siemEvent is the structured record shipped to an external SIEM. JSON over
// HTTP is accepted by Splunk HEC, Elastic, Sumo, and generic log collectors.
type siemEvent struct {
	Timestamp string `json:"timestamp"`
	Source    string `json:"source"`
	Org       string `json:"org"`
	Host      string `json:"host"`
	Type      string `json:"type"`
	Severity  string `json:"severity,omitempty"`
	Technique string `json:"mitre_technique,omitempty"`
	Message   string `json:"message"`
}

// siemForward ships one security event to the configured SIEM endpoint as JSON,
// fire-and-forget. No-op unless --siem-url is set.
func (s *Server) siemForward(org, host, typ, severity, technique, message string) {
	if s.cfg.SIEMURL == "" {
		return
	}
	s.postJSON(s.cfg.SIEMURL, siemEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Source:    "varro",
		Org:       org,
		Host:      host,
		Type:      typ,
		Severity:  severity,
		Technique: technique,
		Message:   message,
	})
}
