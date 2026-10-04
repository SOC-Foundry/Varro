//go:build !linux

package agent

import (
	"context"
	"fmt"
	"runtime"
)

// isolateHost / unisolateHost are implemented only on Linux for now. macOS
// (pf) and Windows (netsh advfirewall) are the natural next targets; until
// then the action fails cleanly rather than pretending to contain the host.
func isolateHost(ctx context.Context, serverURL string) error {
	return fmt.Errorf("host isolation is not yet implemented on %s", runtime.GOOS)
}

func unisolateHost(ctx context.Context) error {
	return fmt.Errorf("host isolation is not yet implemented on %s", runtime.GOOS)
}
