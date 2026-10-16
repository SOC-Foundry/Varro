//go:build !linux

package collect

import (
	"context"

	"github.com/soc-foundry/varro/internal/model"
)

// CollectDeclaredDeps is Linux-only (systemd + Postgres config); elsewhere it
// returns nothing.
func CollectDeclaredDeps(ctx context.Context) []model.DeclaredDep { return nil }
