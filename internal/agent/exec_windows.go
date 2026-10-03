//go:build windows

package agent

import "fmt"

// execSelf is unsupported on Windows: a running executable cannot be replaced
// in place. maybeUpgrade guards against calling this.
func execSelf(string) error {
	return fmt.Errorf("self-upgrade is not supported on windows")
}
