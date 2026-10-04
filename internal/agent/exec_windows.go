//go:build windows

package agent

import "os"

// swapBinary replaces a running executable on Windows: the running file is
// locked against write/delete but can be renamed aside, after which the new
// binary takes its path.
func swapBinary(exe, tmp string) error {
	old := exe + ".old"
	os.Remove(old) // best effort; may remain from a previous upgrade
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Rename(old, exe) // roll back
		return err
	}
	return nil
}

// restartSelf on Windows exits with a failure code so the Service Control
// Manager's recovery action (configured by install.ps1) restarts the service
// on the new binary. Console runs must be restarted manually.
func restartSelf(string) error {
	os.Exit(1)
	return nil
}

// cleanupOldBinary removes the renamed-aside binary from a previous upgrade;
// it couldn't be deleted while it was still running.
func cleanupOldBinary() {
	if exe, err := os.Executable(); err == nil {
		os.Remove(exe + ".old")
	}
}
