package collect

import (
	"context"
	"runtime"
	"testing"
)

// TestCollectLogsSmoke exercises the platform log collector against the real OS
// log source. On Windows (Event Log) and macOS (unified log) the collector is
// expected to work, so an error fails the test — this is what validates the
// otherwise-cross-compile-only logs_windows.go / logs_darwin.go on real hosts in
// CI. On Linux it's lenient (journalctl may be absent in a CI container).
func TestCollectLogsSmoke(t *testing.T) {
	entries, cursor, err := CollectLogs(context.Background(), "", 20)
	if err != nil {
		if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			t.Fatalf("CollectLogs on %s returned an error (the collector should work here): %v", runtime.GOOS, err)
		}
		t.Skipf("no usable log source on %s: %v", runtime.GOOS, err)
	}
	t.Logf("%s: collected %d entries (cursor=%q)", runtime.GOOS, len(entries), cursor)
	// The incremental path (resume from cursor) must also succeed.
	if _, _, err := CollectLogs(context.Background(), cursor, 20); err != nil {
		t.Fatalf("incremental CollectLogs on %s: %v", runtime.GOOS, err)
	}
}
