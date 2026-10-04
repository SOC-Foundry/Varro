//go:build windows

package collect

import (
	"context"
	"sort"

	"golang.org/x/sys/windows/registry"

	"github.com/soc-foundry/varro/internal/model"
)

// uninstallKeys hold installed-program entries (64-bit, 32-bit-on-64).
var uninstallKeys = []string{
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
}

// listPackages enumerates installed programs from the registry uninstall
// keys, the Windows equivalent of a package database.
func listPackages(_ context.Context) (string, []model.Package) {
	seen := map[string]string{}
	for _, path := range uninstallKeys {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
		if err != nil {
			continue
		}
		subs, err := k.ReadSubKeyNames(0)
		k.Close()
		if err != nil {
			continue
		}
		for _, sub := range subs {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+sub, registry.READ)
			if err != nil {
				continue
			}
			name, _, err := sk.GetStringValue("DisplayName")
			if err == nil && name != "" {
				version, _, _ := sk.GetStringValue("DisplayVersion")
				if version == "" {
					version = "unknown"
				}
				seen[name] = version
			}
			sk.Close()
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
	return "windows", pkgs
}
