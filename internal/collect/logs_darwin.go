//go:build darwin

package collect

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

const macLogTS = "2006-01-02 15:04:05.999999-0700"

// CollectLogs reads recent entries from the macOS unified log via `log show`
// (ndjson), since the cursor time, capped to the newest `max`. The cursor is a
// Unix-seconds string; the first run baselines to the last 10 minutes. Any
// failure returns an error so the agent disables log capture — never a crash.
//
// Best-effort: validated by cross-compilation + graceful degrade; field-testing
// on a real macOS host is a follow-up (see docs/agent-platforms.md).
func CollectLogs(ctx context.Context, afterCursor string, max int) ([]model.LogEntry, string, error) {
	from := time.Now().Add(-10 * time.Minute)
	if afterCursor != "" {
		if sec, err := strconv.ParseInt(afterCursor, 10, 64); err == nil {
			from = time.Unix(sec, 0)
		}
	}
	// `log show` --start takes local wall-clock; +1s so we don't re-read the
	// boundary record each poll.
	start := from.Add(time.Second).Format("2006-01-02 15:04:05")
	out, err := exec.CommandContext(ctx, "log", "show", "--style", "ndjson", "--info",
		"--start", start, "--predicate", "eventType == 'logEvent'").Output()
	if err != nil {
		return nil, "", err
	}

	type macEvt struct {
		Timestamp   string `json:"timestamp"`
		Message     string `json:"eventMessage"`
		MessageType string `json:"messageType"`
		Subsystem   string `json:"subsystem"`
		Process     string `json:"processImagePath"`
	}
	var entries []model.LogEntry
	cursorUnix, _ := strconv.ParseInt(afterCursor, 10, 64)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue // skip the ndjson preamble / blank lines
		}
		var e macEvt
		if json.Unmarshal([]byte(line), &e) != nil || e.Message == "" {
			continue
		}
		ts := time.Now().Unix()
		if parsed, err := time.Parse(macLogTS, e.Timestamp); err == nil {
			ts = parsed.Unix()
		}
		src := e.Subsystem
		if src == "" {
			src = baseName(e.Process)
		}
		msg := e.Message
		if len(msg) > 2000 {
			msg = msg[:2000]
		}
		entries = append(entries, model.LogEntry{TS: ts, Severity: macSeverity(e.MessageType), Source: src, Message: msg})
		if ts > cursorUnix {
			cursorUnix = ts
		}
	}
	// Keep the newest `max`.
	if max > 0 && len(entries) > max {
		entries = entries[len(entries)-max:]
	}
	cursor := afterCursor
	if cursorUnix > 0 {
		cursor = strconv.FormatInt(cursorUnix, 10)
	}
	return entries, cursor, nil
}

func macSeverity(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "error":
		return "error"
	case "fault":
		return "critical"
	case "debug":
		return "debug"
	default: // "Default", "Info", unknown
		return "info"
	}
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
