//go:build windows

package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// CollectLogs reads recent Windows Event Log entries (System + Application) via
// PowerShell's Get-WinEvent, newest `max`, since the cursor time. The cursor is
// an RFC3339 timestamp; the first run baselines to the last 10 minutes. Any
// failure (no PowerShell, parse error) returns an error so the agent disables
// log capture — never a crash.
//
// Best-effort: validated by cross-compilation and the graceful-degrade contract;
// field-tested on a real Windows host is a follow-up (see docs/agent-platforms.md).
func CollectLogs(ctx context.Context, afterCursor string, max int) ([]model.LogEntry, string, error) {
	start := afterCursor
	if start == "" {
		start = time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
	}
	// Emit compact per-event JSON objects, oldest→newest.
	ps := fmt.Sprintf(`$ErrorActionPreference='SilentlyContinue';`+
		`Get-WinEvent -FilterHashtable @{LogName=@('System','Application'); StartTime=[datetime]::Parse('%s').ToUniversalTime()} -MaxEvents %d |`+
		`Sort-Object TimeCreated |`+
		`ForEach-Object { [pscustomobject]@{ t=$_.TimeCreated.ToUniversalTime().ToString('o'); lvl=$_.LevelDisplayName; src=$_.ProviderName; msg=$_.Message } } |`+
		`ConvertTo-Json -Compress`, start, max)
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil {
		return nil, "", err
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, afterCursor, nil // no new events
	}

	type winEvt struct {
		T   string `json:"t"`
		Lvl string `json:"lvl"`
		Src string `json:"src"`
		Msg string `json:"msg"`
	}
	// ConvertTo-Json emits a bare object for a single result, an array otherwise.
	var evs []winEvt
	if trimmed[0] == '[' {
		if err := json.Unmarshal([]byte(trimmed), &evs); err != nil {
			return nil, "", err
		}
	} else {
		var one winEvt
		if err := json.Unmarshal([]byte(trimmed), &one); err != nil {
			return nil, "", err
		}
		evs = []winEvt{one}
	}

	var entries []model.LogEntry
	cursor := afterCursor
	for _, e := range evs {
		// StartTime is inclusive — skip anything at/before the cursor to avoid
		// re-emitting the boundary event each poll.
		if afterCursor != "" && e.T <= afterCursor {
			continue
		}
		ts := time.Now().Unix()
		if parsed, err := time.Parse(time.RFC3339, e.T); err == nil {
			ts = parsed.Unix()
		}
		msg := e.Msg
		if len(msg) > 2000 {
			msg = msg[:2000]
		}
		entries = append(entries, model.LogEntry{
			TS: ts, Severity: winSeverity(e.Lvl), Source: e.Src, Message: msg,
		})
		if e.T > cursor {
			cursor = e.T
		}
	}
	return entries, cursor, nil
}

func winSeverity(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return "critical"
	case "error":
		return "error"
	case "warning":
		return "warning"
	case "verbose":
		return "debug"
	default: // "Information" and anything unknown
		return "info"
	}
}
