//go:build windows

package etw

import (
	"os"
	"testing"
	"time"
)

// TestETWGate verifies the opt-in gate: without VARRO_ETW, Start must refuse so
// default Windows agents never touch the experimental ETW session.
func TestETWGate(t *testing.T) {
	os.Unsetenv("VARRO_ETW")
	if _, err := Start(); err == nil {
		t.Fatal("Start should return an error when VARRO_ETW is unset (opt-in gate)")
	}
}

// TestETWExercise actually opens the ETW session and drains events. It only runs
// when VARRO_ETW=1 (the CI runs it as a non-blocking step) — this is what would
// surface a wrong struct layout / syscall fault on a real Windows host.
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
