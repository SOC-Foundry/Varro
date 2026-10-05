//go:build !linux && !darwin && !windows

package agent

import (
	"context"
	"fmt"
	"runtime"
)

// isolateHost / unisolateHost are implemented natively on Linux (nftables/
// iptables), macOS (pf), and Windows (netsh advfirewall). On any other GOOS the
// action fails cleanly rather than pretending to contain the host.
func isolateHost(ctx context.Context, serverURL string) error {
	return fmt.Errorf("host isolation is not yet implemented on %s", runtime.GOOS)
}

func unisolateHost(ctx context.Context) error {
	return fmt.Errorf("host isolation is not yet implemented on %s", runtime.GOOS)
}
