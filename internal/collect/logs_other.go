//go:build !linux && !windows && !darwin

package collect

import (
	"context"
	"errors"

	"github.com/soc-foundry/varro/internal/model"
)

// CollectLogs is a no-op on platforms without a supported log source (Linux uses
// journald, Windows the Event Log, macOS the unified log). The error lets the
// agent disable log capture after one attempt.
func CollectLogs(ctx context.Context, afterCursor string, max int) ([]model.LogEntry, string, error) {
	return nil, "", errors.New("log capture not supported on this platform")
}
