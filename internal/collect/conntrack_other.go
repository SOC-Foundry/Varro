//go:build !linux

package collect

import "github.com/soc-foundry/varro/internal/model"

// sampleFlows is Linux-only (reads the netfilter conntrack table).
func (c *Collector) sampleFlows(*model.Snapshot) {}
