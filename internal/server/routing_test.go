package server

import (
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestAlertSeverity(t *testing.T) {
	cases := []struct {
		state, rule, want string
	}{
		{"resolved", "synthetic-down", model.SevInfo},
		{"resolved", "high-cpu", model.SevInfo},
		{"firing", "synthetic-down", model.SevCritical},
		{"firing", "service-error-rate", model.SevCritical},
		{"firing", "high-cpu", model.SevWarning},
		{"firing", "offline", model.SevWarning},
	}
	for _, c := range cases {
		if got := alertSeverity(c.state, c.rule); got != c.want {
			t.Errorf("alertSeverity(%q,%q) = %q, want %q", c.state, c.rule, got, c.want)
		}
	}
}

func TestEventSeverity(t *testing.T) {
	if eventSeverity(model.EventThreatMatch) != model.SevCritical {
		t.Error("threat match should be critical")
	}
	if eventSeverity(model.EventListenNew) != model.SevWarning {
		t.Error("listen_new should be warning")
	}
}

func TestSevRankFilter(t *testing.T) {
	// A critical alert reaches a warning-min route; a warning alert does not
	// reach a critical-min route.
	if !(sevRank[model.SevCritical] >= sevRank[model.SevWarning]) {
		t.Error("critical should meet a warning-min route")
	}
	if sevRank[model.SevWarning] >= sevRank[model.SevCritical] {
		t.Error("warning should NOT meet a critical-min route")
	}
}

func TestValidateRoute(t *testing.T) {
	ok := []struct{ typ, target, sev string }{
		{model.RouteWebhook, "https://hooks.example/x", "warning"},
		{model.RouteSlack, "https://hooks.slack.com/services/x", ""},
		{model.RoutePagerDuty, "r0uting-key-123", "critical"},
		{model.RouteOpsgenie, "genie-key-123", "info"},
	}
	for _, c := range ok {
		r, err := validateRoute(c.typ, c.target, c.sev)
		if err != nil {
			t.Errorf("validateRoute(%q,%q,%q) unexpected error: %v", c.typ, c.target, c.sev, err)
			continue
		}
		if c.sev == "" && r.MinSeverity != model.SevWarning {
			t.Errorf("empty severity should default to warning, got %q", r.MinSeverity)
		}
	}

	bad := []struct{ desc, typ, target, sev string }{
		{"empty target", model.RouteWebhook, "", "warning"},
		{"webhook not url", model.RouteWebhook, "not-a-url", "warning"},
		{"slack bad scheme", model.RouteSlack, "ftp://x", "warning"},
		{"unknown type", "sms", "+15551234567", "warning"},
		{"bad severity", model.RouteWebhook, "https://x.example", "urgent"},
	}
	for _, c := range bad {
		if _, err := validateRoute(c.typ, c.target, c.sev); err == nil {
			t.Errorf("validateRoute %s: expected error, got none", c.desc)
		}
	}
}
