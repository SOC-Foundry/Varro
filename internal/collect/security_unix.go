//go:build !windows

package collect

import (
	"os"
	"path/filepath"
)

// autostartRoots are filesystem locations where persistence is commonly
// established. Watched as a flat (path -> size/mtime) fingerprint; any
// add/modify/remove is an event.
func autostartRoots() []string {
	roots := []string{
		"/etc/systemd/system",
		"/etc/init.d",
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/crontab",
		"/etc/rc.local",
	}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, ".config", "autostart"))
	}
	return roots
}

func platformAutostartExtras() map[string]string { return nil }

// identityPaths are the files that define who can log in and escalate.
// Changing any of them is one of the highest-signal events an endpoint emits.
func identityPaths() []string {
	paths := []string{
		"/etc/passwd",
		"/etc/group",
		"/etc/shadow",
		"/etc/sudoers",
		"/root/.ssh/authorized_keys",
	}
	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range entries {
			paths = append(paths, filepath.Join("/etc/sudoers.d", e.Name()))
		}
	}
	if homes, err := os.ReadDir("/home"); err == nil {
		for _, h := range homes {
			paths = append(paths, filepath.Join("/home", h.Name(), ".ssh", "authorized_keys"))
		}
	}
	return paths
}
