//go:build !windows

package etw

import (
	"errors"

	"github.com/soc-foundry/varro/internal/model"
)

// Tracer is a no-op outside Windows.
type Tracer struct{}

// Start always fails off Windows (ETW is Windows-only); the agent falls back to
// the eBPF (Linux) or polling (other) exec sensor.
func Start() (*Tracer, error) { return nil, errors.New("ETW is Windows-only") }

func (t *Tracer) Drain() []model.ExecSample { return nil }
func (t *Tracer) Close()                    {}
