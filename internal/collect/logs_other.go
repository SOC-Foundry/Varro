//go:build !linux

package collect

import (
	"context"
	"errors"

	"github.com/soc-foundry/varro/internal/model"
)

// CollectLogs is a no-op on non-Linux platforms (journald-only for now). The
// error lets the agent disable log capture after one attempt.
func CollectLogs(ctx context.Context, afterCursor string, max int) ([]model.LogEntry, string, error) {
	return nil, "", errors.New("log capture not supported on this platform")
}
