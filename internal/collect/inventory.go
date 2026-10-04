package collect

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/host"

	"github.com/soc-foundry/varro/internal/model"
)

const (
	inventoryScanEvery = 10 * time.Minute
	maxPkgEvents       = 20
	pkgCmdTimeout      = 30 * time.Second
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

// sampleInventory scans installed packages every inventoryScanEvery, emits
// change events, and attaches the full inventory to the snapshot only when it
// differs from the last one shipped.
func (c *Collector) sampleInventory(ctx context.Context, now time.Time, snap *model.Snapshot) {
	if !c.lastInvScan.IsZero() && now.Sub(c.lastInvScan) < inventoryScanEvery {
		return
	}
	c.lastInvScan = now

	manager, pkgs := listPackages(ctx)
	if manager == "" {
		return
	}

	current := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		current[p.Name] = p.Version
	}

	changed := c.prevPackages == nil
	if c.prevPackages != nil {
		n := 0
		emit := func(typ, msg string) {
			changed = true
			if n < maxPkgEvents {
				snap.Events = append(snap.Events, model.Event{Type: typ, Message: msg})
				n++
			}
		}
		for name, ver := range current {
			prev, ok := c.prevPackages[name]
			if !ok {
				emit(model.EventPkgInstall, fmt.Sprintf("package installed: %s %s", name, ver))
			} else if prev != ver {
				emit(model.EventPkgUpgrade, fmt.Sprintf("package upgraded: %s %s -> %s", name, prev, ver))
			}
		}
		for name, ver := range c.prevPackages {
			if _, ok := current[name]; !ok {
				emit(model.EventPkgRemove, fmt.Sprintf("package removed: %s %s", name, ver))
			}
		}
	}
	c.prevPackages = current

	if changed {
		kernel := ""
		if info, err := host.InfoWithContext(ctx); err == nil {
			kernel = info.KernelVersion
		}
		// Park it as pending rather than attaching directly: the snapshot
		// this scan ran in may be discarded (the agent's priming sample) or
		// fail to ship. Every snapshot carries the pending inventory until
		// the agent confirms delivery via InventoryDelivered.
		c.pendingInv = &model.Inventory{
			Kernel:   kernel,
			Manager:  manager,
			Packages: pkgs,
		}
	}
}

// InventoryDelivered is called by the agent once a batch containing the
// pending inventory has been accepted by the collector.
func (c *Collector) InventoryDelivered() { c.pendingInv = nil }

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
