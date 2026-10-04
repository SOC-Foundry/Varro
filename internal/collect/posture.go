package collect

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

const postureScanEvery = 10 * time.Minute

// samplePosture recomputes the CIS-lite checks every postureScanEvery and
// carries the cached result on every snapshot. Transitions emit events.
func (c *Collector) samplePosture(ctx context.Context, now time.Time, snap *model.Snapshot) {
	if c.lastPosture == nil || now.Sub(c.lastPostureScan) >= postureScanEvery {
		fresh := runPostureChecks(ctx)
		if c.lastPosture != nil {
			prev := map[string]string{}
			for _, p := range c.lastPosture {
				prev[p.ID] = p.Status
			}
			for _, p := range fresh {
				if old, ok := prev[p.ID]; ok && old != p.Status {
					snap.Events = append(snap.Events, model.Event{
						Type:    model.EventPostureChange,
						Message: "posture check " + p.ID + " changed " + old + " -> " + p.Status + ": " + p.Detail,
					})
				}
			}
		}
		c.lastPosture = fresh
		c.lastPostureScan = now
	}
	snap.Posture = c.lastPosture
}

// PostureFails counts failing checks.
func PostureFails(checks []model.PostureCheck) int {
	n := 0
	for _, p := range checks {
		if p.Status == model.PostureFail {
			n++
		}
	}
	return n
}

func runPostureChecks(ctx context.Context) []model.PostureCheck {
	return []model.PostureCheck{
		checkSSHOption(ctx, "ssh_root_login", "SSH root login disabled", "PermitRootLogin", []string{"no", "prohibit-password", "without-password"}),
		checkSSHOption(ctx, "ssh_password_auth", "SSH password authentication disabled", "PasswordAuthentication", []string{"no"}),
		checkFirewall(ctx),
		checkDiskEncryption(ctx),
		checkAutoUpdates(ctx),
		checkTimeSync(ctx),
		checkMAC(ctx),
		checkAgentPrivilege(),
	}
}

func check(id, desc, status, detail string) model.PostureCheck {
	return model.PostureCheck{ID: id, Desc: desc, Status: status, Detail: detail}
}

// run executes a command with a short timeout, returning combined trimmed
// stdout and whether it exited zero.
func run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, bool) {
	if _, err := exec.LookPath(name); err != nil {
		return "", false
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).Output()
	return strings.TrimSpace(string(out)), err == nil
}

// sshdOption returns the first effective value of an sshd_config option
// (first occurrence wins in OpenSSH), searching the main file then conf.d.
func sshdOption(name string) (string, bool) {
	files := []string{"/etc/ssh/sshd_config"}
	if matches, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		files = append(files, matches...)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.EqualFold(fields[0], name) {
				return strings.ToLower(fields[1]), true
			}
		}
	}
	return "", false
}

func checkSSHOption(ctx context.Context, id, desc, option string, good []string) model.PostureCheck {
	if _, err := os.Stat("/etc/ssh/sshd_config"); err != nil {
		return check(id, desc, model.PostureNA, "no sshd configuration present")
	}
	val, found := sshdOption(option)
	if !found {
		// OpenSSH defaults: PermitRootLogin prohibit-password (acceptable),
		// PasswordAuthentication yes (not acceptable).
		if option == "PermitRootLogin" {
			return check(id, desc, model.PosturePass, "not set; default prohibit-password")
		}
		return check(id, desc, model.PostureFail, option+" not set; OpenSSH defaults to yes")
	}
	for _, g := range good {
		if val == g {
			return check(id, desc, model.PosturePass, option+" "+val)
		}
	}
	return check(id, desc, model.PostureFail, option+" "+val)
}

func checkFirewall(ctx context.Context) model.PostureCheck {
	const id, desc = "firewall", "Host firewall active"
	switch runtime.GOOS {
	case "linux":
		if out, ok := run(ctx, 5*time.Second, "ufw", "status"); ok && strings.Contains(out, "Status: active") {
			return check(id, desc, model.PosturePass, "ufw active")
		}
		if out, ok := run(ctx, 5*time.Second, "systemctl", "is-active", "firewalld"); ok && out == "active" {
			return check(id, desc, model.PosturePass, "firewalld active")
		}
		if out, ok := run(ctx, 5*time.Second, "nft", "list", "ruleset"); ok {
			if len(strings.Split(out, "\n")) > 5 {
				return check(id, desc, model.PosturePass, "nftables ruleset loaded")
			}
		}
		if out, ok := run(ctx, 5*time.Second, "iptables", "-S"); ok {
			if len(strings.Split(out, "\n")) > 3 {
				return check(id, desc, model.PosturePass, "iptables rules present")
			}
			return check(id, desc, model.PostureFail, "no firewall rules loaded")
		}
		return check(id, desc, model.PostureNA, "no firewall tooling found")
	case "darwin":
		if out, ok := run(ctx, 5*time.Second, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"); ok {
			if strings.Contains(strings.ToLower(out), "enabled") {
				return check(id, desc, model.PosturePass, "application firewall enabled")
			}
			return check(id, desc, model.PostureFail, "application firewall disabled")
		}
	case "windows":
		if out, ok := run(ctx, 10*time.Second, "netsh", "advfirewall", "show", "allprofiles", "state"); ok {
			if strings.Contains(out, "ON") {
				return check(id, desc, model.PosturePass, "windows firewall on")
			}
			return check(id, desc, model.PostureFail, "windows firewall off")
		}
	}
	return check(id, desc, model.PostureNA, "not determinable")
}

func checkDiskEncryption(ctx context.Context) model.PostureCheck {
	const id, desc = "disk_encryption", "Disk encryption in use"
	switch runtime.GOOS {
	case "linux":
		if out, ok := run(ctx, 5*time.Second, "lsblk", "-o", "TYPE", "--noheadings"); ok {
			if strings.Contains(out, "crypt") {
				return check(id, desc, model.PosturePass, "dm-crypt volume present")
			}
			return check(id, desc, model.PostureFail, "no encrypted block devices")
		}
	case "darwin":
		if out, ok := run(ctx, 10*time.Second, "fdesetup", "status"); ok {
			if strings.Contains(out, "On") {
				return check(id, desc, model.PosturePass, "FileVault on")
			}
			return check(id, desc, model.PostureFail, "FileVault off")
		}
	case "windows":
		if out, ok := run(ctx, 15*time.Second, "manage-bde", "-status", "C:"); ok {
			if strings.Contains(out, "Percentage Encrypted: 100") {
				return check(id, desc, model.PosturePass, "BitLocker fully encrypted")
			}
			return check(id, desc, model.PostureFail, "C: not fully BitLocker-encrypted")
		}
	}
	return check(id, desc, model.PostureNA, "not determinable")
}

func checkAutoUpdates(ctx context.Context) model.PostureCheck {
	const id, desc = "auto_updates", "Automatic security updates enabled"
	switch runtime.GOOS {
	case "linux":
		if data, err := os.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades"); err == nil {
			if strings.Contains(string(data), `Unattended-Upgrade "1"`) {
				return check(id, desc, model.PosturePass, "unattended-upgrades enabled")
			}
			return check(id, desc, model.PostureFail, "unattended-upgrades disabled")
		}
		if _, err := os.Stat("/etc/apt"); err == nil {
			return check(id, desc, model.PostureFail, "unattended-upgrades not configured")
		}
		if out, ok := run(ctx, 5*time.Second, "systemctl", "is-enabled", "dnf-automatic.timer"); ok && out == "enabled" {
			return check(id, desc, model.PosturePass, "dnf-automatic enabled")
		}
	case "darwin":
		if out, ok := run(ctx, 10*time.Second, "softwareupdate", "--schedule"); ok {
			if strings.Contains(strings.ToLower(out), "on") {
				return check(id, desc, model.PosturePass, "automatic checking on")
			}
			return check(id, desc, model.PostureFail, "automatic checking off")
		}
	}
	return check(id, desc, model.PostureNA, "not determinable on this platform")
}

func checkTimeSync(ctx context.Context) model.PostureCheck {
	const id, desc = "time_sync", "System clock NTP-synchronized"
	if runtime.GOOS == "linux" {
		if out, ok := run(ctx, 5*time.Second, "timedatectl", "show", "--property=NTPSynchronized", "--value"); ok {
			if out == "yes" {
				return check(id, desc, model.PosturePass, "NTP synchronized")
			}
			return check(id, desc, model.PostureFail, "clock not NTP-synchronized")
		}
	}
	return check(id, desc, model.PostureNA, "not determinable")
}

func checkMAC(ctx context.Context) model.PostureCheck {
	const id, desc = "mandatory_access_control", "SELinux/AppArmor enforcing"
	if runtime.GOOS != "linux" {
		return check(id, desc, model.PostureNA, "linux-only check")
	}
	if out, ok := run(ctx, 5*time.Second, "getenforce"); ok {
		if out == "Enforcing" {
			return check(id, desc, model.PosturePass, "SELinux enforcing")
		}
		return check(id, desc, model.PostureFail, "SELinux "+strings.ToLower(out))
	}
	if data, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		if strings.TrimSpace(string(data)) == "Y" {
			return check(id, desc, model.PosturePass, "AppArmor enabled")
		}
		return check(id, desc, model.PostureFail, "AppArmor present but disabled")
	}
	return check(id, desc, model.PostureFail, "no MAC system active")
}

func checkAgentPrivilege() model.PostureCheck {
	const id, desc = "agent_privilege", "Varro agent running with full telemetry access"
	if runtime.GOOS == "windows" {
		return check(id, desc, model.PosturePass, "service runs as SYSTEM")
	}
	if os.Geteuid() == 0 {
		return check(id, desc, model.PosturePass, "running as root")
	}
	return check(id, desc, model.PostureFail, "running unprivileged; auth log and some processes invisible")
}
