package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// CFEmailConfig sends mail through Cloudflare Email Service's REST API —
// preferred over SMTP when configured (no relay or credentials-in-transit).
type CFEmailConfig struct {
	AccountID string
	Token     string
	From      string // sender address at a domain onboarded to Email Sending
}

// GmailConfig sends via the Gmail API using a service account with
// domain-wide delegation — for deployments where outbound SMTP is blocked
// (e.g. Cloud Run) and the Workspace admin has authorized the service
// account's client ID for the gmail.send scope.
type GmailConfig struct {
	SAKeyPath string // path to the service-account JSON key file
	SendAs    string // the Workspace user to impersonate; also the From address
}

func (s *Server) cfEmailEnabled() bool {
	return s.cfg.CFEmail.Token != "" && s.cfg.CFEmail.AccountID != "" && s.cfg.CFEmail.From != ""
}

func (s *Server) gmailEnabled() bool {
	return s.cfg.Gmail.SAKeyPath != "" && s.cfg.Gmail.SendAs != ""
}

// mailEnabled reports whether any outbound email transport is configured.
// Transports in precedence order: Gmail API, Cloudflare, SMTP relay.
func (s *Server) mailEnabled() bool {
	return s.gmailEnabled() || s.cfEmailEnabled() || s.cfg.SMTP.Host != ""
}

// sendViaCloudflare posts one message to the Email Sending API.
func (s *Server) sendViaCloudflare(to []string, subject, body string) {
	payload, err := json.Marshal(map[string]any{
		"to":      to,
		"from":    map[string]string{"address": s.cfg.CFEmail.From, "name": "Varro"},
		"subject": subject,
		"text":    body,
	})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/email/sending/send",
		s.cfg.CFEmail.AccountID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.CFEmail.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.log.Error("cloudflare email send failed", "error", err)
		return
	}
	defer resp.Body.Close()
	var out struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result struct {
			Delivered        []string `json:"delivered"`
			PermanentBounces []string `json:"permanent_bounces"`
			Queued           []string `json:"queued"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		s.log.Error("cloudflare email response unreadable", "status", resp.Status)
		return
	}
	if !out.Success {
		msg := resp.Status
		if len(out.Errors) > 0 {
			msg = fmt.Sprintf("%d: %s", out.Errors[0].Code, out.Errors[0].Message)
		}
		s.log.Error("cloudflare email rejected", "error", msg)
		return
	}
	if len(out.Result.PermanentBounces) > 0 {
		s.log.Warn("cloudflare email bounced", "addresses", out.Result.PermanentBounces)
	}
	s.log.Info("email sent via cloudflare", "to", to, "subject", subject,
		"delivered", len(out.Result.Delivered), "queued", len(out.Result.Queued))
}
