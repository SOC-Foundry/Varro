//go:build !windows

package collect

import (
	"os"
	"path/filepath"
	"runtime"
)

// autostartRoots are filesystem locations where persistence is commonly
// established. Watched as a flat (path -> size/mtime) fingerprint; any
// add/modify/remove is an event.
func autostartRoots() []string {
	var roots []string
	if runtime.GOOS == "darwin" {
		roots = []string{
			"/Library/LaunchDaemons",
			"/Library/LaunchAgents",
			"/usr/lib/cron/tabs",
			"/etc/periodic",
		}
		if users, err := os.ReadDir("/Users"); err == nil {
			for _, u := range users {
				roots = append(roots, filepath.Join("/Users", u.Name(), "Library", "LaunchAgents"))
			}
		}
		return roots
	}
	roots = []string{
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
		"/etc/sudoers",
	}
	if runtime.GOOS != "darwin" {
		paths = append(paths, "/etc/passwd", "/etc/group", "/etc/shadow")
	}
	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range entries {
			paths = append(paths, filepath.Join("/etc/sudoers.d", e.Name()))
		}
	}
	// Root's SSH keys live in different homes per OS.
	paths = append(paths, "/root/.ssh/authorized_keys", "/var/root/.ssh/authorized_keys")
	for _, dir := range []string{"/home", "/Users"} {
		if homes, err := os.ReadDir(dir); err == nil {
			for _, h := range homes {
				paths = append(paths, filepath.Join(dir, h.Name(), ".ssh", "authorized_keys"))
			}
		}
	}
	return paths
}
