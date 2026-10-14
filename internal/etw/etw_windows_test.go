//go:build windows

package etw

import (
	"os"
	"testing"
	"time"
)

// TestETWExercise opens the ETW session and drains events — this is what would
// surface a wrong struct layout / syscall fault on a real Windows host. It only
// runs when VARRO_ETW=1 (the CI runs it as a dedicated step) so the main suite
// doesn't open a live kernel trace on every run.
func TestETWExercise(t *testing.T) {
	if os.Getenv("VARRO_ETW") == "" {
		t.Skip("set VARRO_ETW=1 to exercise the live ETW session")
	}
	tr, err := Start()
	if err != nil {
		t.Fatalf("ETW Start: %v", err)
	}
	defer tr.Close()
	time.Sleep(2 * time.Second)
	t.Logf("ETW drained %d process-start events", len(tr.Drain()))
}
