package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/soc-foundry/varro/internal/model"
)

// handleCICD ingests a CI/CD pipeline event (build/deploy/release) from a
// webhook and records it as a server event, so it shows in the events feed, as
// a deploy marker on metric charts, and flows to SIEM/notifications. Auth is the
// same token->org resolution as OTLP (master or org enrollment token).
func (s *Server) handleCICD(w http.ResponseWriter, r *http.Request) {
	org, ok := s.otlpOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Event   string `json:"event"`   // deploy | build | release | rollback (free text)
		Service string `json:"service"` // app/pipeline name
		Status  string `json:"status"`  // success | failure | started
		Ref     string `json:"ref"`     // branch/tag
		Version string `json:"version"` // version/sha
		URL     string `json:"url"`     // link to the run
		Message string `json:"message"` // optional free text
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	event := strings.TrimSpace(req.Event)
	if event == "" {
		event = "deploy"
	}
	service := strings.TrimSpace(req.Service)
	if service == "" {
		service = "unknown"
	}

	// Compose a human-readable one-liner: "deploy checkout → success (v1.2.3 @ main)".
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", event, service)
	if req.Status != "" {
		fmt.Fprintf(&b, " → %s", req.Status)
	}
	var det []string
	if req.Version != "" {
		det = append(det, req.Version)
	}
	if req.Ref != "" {
		det = append(det, "@"+req.Ref)
	}
	if len(det) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(det, " "))
	}
	if req.Message != "" {
		fmt.Fprintf(&b, " — %s", req.Message)
	}
	if req.URL != "" {
		fmt.Fprintf(&b, " %s", req.URL)
	}

	if err := s.store.InsertServerEvent(r.Context(), org, "ci/"+service, model.EventCICD, b.String()); err != nil {
		s.log.Error("cicd ingest failed", "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	// Reuse the event-forwarding path so CI events reach SIEM/notifiers too.
	s.siemForward(org, service, model.EventCICD, "INFO", "", b.String())
	writeJSON(w, map[string]bool{"recorded": true})
}
