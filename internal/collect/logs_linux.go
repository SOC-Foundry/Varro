//go:build linux

package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strconv"

	"github.com/soc-foundry/varro/internal/model"
)

// journald PRIORITY (0..7) → syslog severity name.
var sysloSeverity = [...]string{
	"emergency", "alert", "critical", "error", "warning", "notice", "info", "debug",
}

const logMsgCap = 2000

// CollectLogs reads up to max new journal entries after the given cursor (an
// opaque journald position). On the first run (empty cursor) it takes the last
// `max` entries as a baseline. It returns the entries plus the cursor to resume
// from next time. A missing journalctl (non-systemd host) returns an error so
// the caller can disable log capture.
func CollectLogs(ctx context.Context, afterCursor string, max int) ([]model.LogEntry, string, error) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, "", err
	}
	args := []string{"-o", "json", "--no-pager", "-n", strconv.Itoa(max)}
	if afterCursor != "" {
		args = append(args, "--after-cursor="+afterCursor)
	}
	out, err := exec.CommandContext(ctx, "journalctl", args...).Output()
	if err != nil {
		return nil, "", err
	}

	var entries []model.LogEntry
	cursor := afterCursor
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		// journald fields are mostly strings, but MESSAGE may be an array for
		// non-UTF8 payloads — decode leniently and skip what we can't read.
		var rec map[string]json.RawMessage
		if err := dec.Decode(&rec); err != nil {
			break
		}
		msg := jsonString(rec["MESSAGE"])
		if msg == "" {
			continue
		}
		if len(msg) > logMsgCap {
			msg = msg[:logMsgCap] + "…"
		}
		e := model.LogEntry{Message: msg}
		if ts := jsonString(rec["__REALTIME_TIMESTAMP"]); ts != "" {
			if usec, err := strconv.ParseInt(ts, 10, 64); err == nil {
				e.TS = usec / 1_000_000
			}
		}
		if p := jsonString(rec["PRIORITY"]); p != "" {
			if n, err := strconv.Atoi(p); err == nil && n >= 0 && n < len(sysloSeverity) {
				e.Severity = sysloSeverity[n]
			}
		}
		if u := jsonString(rec["_SYSTEMD_UNIT"]); u != "" {
			e.Source = u
		} else if id := jsonString(rec["SYSLOG_IDENTIFIER"]); id != "" {
			e.Source = id
		}
		entries = append(entries, e)
		if c := jsonString(rec["__CURSOR"]); c != "" {
			cursor = c
		}
	}
	return entries, cursor, nil
}

// jsonString returns the string value of a journald field, or "" when the field
// is absent or isn't a plain JSON string (e.g. a byte array).
func jsonString(raw json.RawMessage) string {
	if len(raw) == 0 || raw[0] != '"' {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}
