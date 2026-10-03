//go:build !windows

package agent

import (
	"os"
	"syscall"
)

// execSelf replaces the current process with the binary at path, preserving
// arguments and environment. Only returns on error.
func execSelf(path string) error {
	return syscall.Exec(path, os.Args, os.Environ())
}
