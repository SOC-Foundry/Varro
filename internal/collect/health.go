package collect

import (
	"context"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

const healthScanEvery = 10 * time.Minute

// sampleHealth recomputes patch/service health every healthScanEvery and
// carries the cached result on every snapshot. Newly failed services and a
// newly required reboot emit events.
func (c *Collector) sampleHealth(ctx context.Context, now time.Time, snap *model.Snapshot) {
	if c.lastHealthScan.IsZero() || now.Sub(c.lastHealthScan) >= healthScanEvery {
		fresh := collectHealth(ctx)

		if !c.lastHealthScan.IsZero() {
			prevFailed := map[string]bool{}
			for _, s := range c.lastHealth.FailedServices {
				prevFailed[s] = true
			}
			n := 0
			for _, svc := range fresh.FailedServices {
				if !prevFailed[svc] && n < 10 {
					snap.Events = append(snap.Events, model.Event{
						Type:    model.EventServiceFailed,
						Message: "service entered failed state: " + svc,
					})
					n++
				}
			}
			if fresh.RebootRequired && !c.lastHealth.RebootRequired {
				snap.Events = append(snap.Events, model.Event{
					Type:    model.EventRebootRequired,
					Message: "reboot required to apply updates",
				})
			}
		}
		c.lastHealth = fresh
		c.lastHealthScan = now
	}
	snap.Health = c.lastHealth
}

func collectHealth(ctx context.Context) model.HealthStatus {
	return model.HealthStatus{
		PendingUpdates: pendingUpdates(ctx),
		RebootRequired: rebootRequired(ctx),
		FailedServices: failedServices(ctx),
	}
}

func pendingUpdates(ctx context.Context) int {
	countLines := func(out string, match func(string) bool) int {
		n := 0
		for _, line := range strings.Split(out, "\n") {
			if line != "" && (match == nil || match(line)) {
				n++
			}
		}
		return n
	}
	switch runtime.GOOS {
	case "linux":
		if out, ok := run(ctx, 60*time.Second, "apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade"); ok {
			return countLines(out, func(l string) bool { return strings.HasPrefix(l, "Inst ") })
		}
		// checkupdates (pacman-contrib) is sync-safe; plain -Qu compares
		// against the possibly stale local db but is better than nothing.
		if out, ok := run(ctx, 60*time.Second, "checkupdates"); ok {
			return countLines(out, nil)
		}
		if out, ok := run(ctx, 30*time.Second, "pacman", "-Qu"); ok {
			return countLines(out, nil)
		}
		if out, _ := run(ctx, 60*time.Second, "dnf", "-q", "check-update"); out != "" {
			return countLines(out, func(l string) bool { return !strings.HasPrefix(l, " ") && strings.Contains(l, ".") })
		}
	case "darwin":
		if out, ok := run(ctx, 90*time.Second, "softwareupdate", "-l"); ok {
			return countLines(out, func(l string) bool { return strings.Contains(l, "* Label:") })
		}
	}
	return 0
}

func rebootRequired(ctx context.Context) bool {
	switch runtime.GOOS {
	case "linux":
		if _, err := os.Stat("/var/run/reboot-required"); err == nil {
			return true
		}
		if _, ok := run(ctx, 30*time.Second, "needs-restarting", "-r"); ok {
			return false // exit 0 = no reboot needed
		}
	case "windows":
		if _, ok := run(ctx, 10*time.Second, "reg", "query",
			`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`); ok {
			return true
		}
	}
	return false
}

func failedServices(ctx context.Context) []string {
	var out []string
	switch runtime.GOOS {
	case "linux":
		if res, ok := run(ctx, 10*time.Second, "systemctl", "--failed", "--plain", "--no-legend"); ok && res != "" {
			for _, line := range strings.Split(res, "\n") {
				if fields := strings.Fields(line); len(fields) > 0 {
					name := strings.TrimPrefix(fields[0], "●")
					if name = strings.TrimSpace(name); name != "" {
						out = append(out, name)
					}
				}
			}
		}
	case "windows":
		if res, ok := run(ctx, 30*time.Second, "powershell", "-NoProfile", "-Command",
			"Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'} | Select-Object -ExpandProperty Name"); ok && res != "" {
			for _, line := range strings.Split(res, "\n") {
				if name := strings.TrimSpace(line); name != "" {
					out = append(out, name)
				}
			}
		}
	}
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}
