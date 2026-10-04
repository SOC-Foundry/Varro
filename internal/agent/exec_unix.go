//go:build !windows

package agent

import (
	"os"
	"syscall"
)

// swapBinary atomically replaces the (possibly running) executable at exe
// with the file at tmp.
func swapBinary(exe, tmp string) error {
	return os.Rename(tmp, exe)
}

// restartSelf replaces the current process with the binary at path,
// preserving arguments and environment. Only returns on error.
func restartSelf(path string) error {
	return syscall.Exec(path, os.Args, os.Environ())
}

// cleanupOldBinary is a no-op on unix (the swap leaves nothing behind).
func cleanupOldBinary() {}
