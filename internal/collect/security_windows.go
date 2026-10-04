//go:build windows

package collect

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// autostartRoots on Windows are the Startup folders (all-users and the
// current account's, which for the service is SYSTEM).
func autostartRoots() []string {
	var roots []string
	if pd := os.Getenv("ProgramData"); pd != "" {
		roots = append(roots, filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs\StartUp`))
	}
	if ad := os.Getenv("APPDATA"); ad != "" {
		roots = append(roots, filepath.Join(ad, `Microsoft\Windows\Start Menu\Programs\Startup`))
	}
	return roots
}

// runKeys are the classic registry persistence locations.
var runKeys = []struct {
	root registry.Key
	path string
	name string
}{
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Run`},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\RunOnce`},
	{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, `HKLM\WOW6432\Run`},
}

// platformAutostartExtras fingerprints registry Run/RunOnce values so a new
// or changed autostart entry raises an autostart_change event.
func platformAutostartExtras() map[string]string {
	out := map[string]string{}
	for _, rk := range runKeys {
		k, err := registry.OpenKey(rk.root, rk.path, registry.READ)
		if err != nil {
			continue
		}
		names, err := k.ReadValueNames(0)
		if err == nil {
			for _, n := range names {
				if v, _, err := k.GetStringValue(n); err == nil {
					out[rk.name+`\`+n] = v
				}
			}
		}
		k.Close()
	}
	return out
}

// identityPaths has no Windows equivalent yet (local account changes would
// come from the SAM / event log — future work).
func identityPaths() []string { return nil }
