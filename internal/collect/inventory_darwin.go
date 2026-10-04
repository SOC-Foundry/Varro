//go:build darwin

package collect

import (
	"context"
	"encoding/json"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// system_profiler enumerates every installed application but can take tens of
// seconds; it gets a generous timeout and only runs every inventory scan.
const profilerTimeout = 90 * time.Second

// listPackages inventories macOS software: installed applications via
// system_profiler, plus Homebrew formulae when brew is present.
func listPackages(ctx context.Context) (string, []model.Package) {
	seen := map[string]string{}

	pctx, cancel := context.WithTimeout(ctx, profilerTimeout)
	out, err := exec.CommandContext(pctx, "system_profiler", "-json", "SPApplicationsDataType").Output()
	cancel()
	if err == nil {
		var doc struct {
			Apps []struct {
				Name    string `json:"_name"`
				Version string `json:"version"`
			} `json:"SPApplicationsDataType"`
		}
		if json.Unmarshal(out, &doc) == nil {
			for _, a := range doc.Apps {
				if a.Name == "" {
					continue
				}
				v := a.Version
				if v == "" {
					v = "unknown"
				}
				seen[a.Name] = v
			}
		}
	}

	if _, err := exec.LookPath("brew"); err == nil {
		bctx, cancel := context.WithTimeout(ctx, pkgCmdTimeout)
		out, err := exec.CommandContext(bctx, "brew", "list", "--versions").Output()
		cancel()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					seen["brew:"+fields[0]] = fields[1]
				}
			}
		}
	}

	if len(seen) == 0 {
		return "", nil
	}
	pkgs := make([]model.Package, 0, len(seen))
	for name, ver := range seen {
		pkgs = append(pkgs, model.Package{Name: name, Version: ver})
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	return "macos", pkgs
}
