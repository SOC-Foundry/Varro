//go:build !windows

package collect

import (
	"context"
	"os/exec"
	"sort"
	"strings"

	"github.com/soc-foundry/varro/internal/model"
)

// packageManagers in detection order: command + args producing
// "name<space>version" lines.
var packageManagers = []struct {
	name string
	cmd  string
	args []string
}{
	{"dpkg", "dpkg-query", []string{"-W", "-f", "${Package} ${Version}\n"}},
	{"rpm", "rpm", []string{"-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"}},
	{"pacman", "pacman", []string{"-Q"}},
}

func listPackages(ctx context.Context) (string, []model.Package) {
	for _, pm := range packageManagers {
		if _, err := exec.LookPath(pm.cmd); err != nil {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, pkgCmdTimeout)
		out, err := exec.CommandContext(cctx, pm.cmd, pm.args...).Output()
		cancel()
		if err != nil {
			continue
		}
		var pkgs []model.Package
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pkgs = append(pkgs, model.Package{Name: fields[0], Version: fields[1]})
			}
		}
		if len(pkgs) == 0 {
			continue
		}
		sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
		return pm.name, pkgs
	}
	return "", nil
}
