package collect

import "testing"

func TestSensitiveWrite(t *testing.T) {
	cases := map[string]bool{
		"/etc/cron.d/backup":            true,
		"/etc/systemd/system/x.service": true,
		"/etc/sudoers":                  true,
		"/etc/passwd":                   true,
		"/etc/ssh/sshd_config":          true,
		"/etc/ld.so.preload":            true,
		"/boot/grub/grub.cfg":           true,
		"/root/.ssh/authorized_keys":    true,
		"/root/.bashrc":                 true,
		// routine churn under the roots: excluded
		"/etc/resolv.conf":      false,
		"/etc/ld.so.cache":      false,
		"/etc/ssl/certs/ca.pem": false,
		"/etc/machine-id":       false,
		"/etc/mtab.lock":        false,
		"/etc/foo.swp":          false,
		// outside the roots (kernel gate should prevent these, defense in depth)
		"/tmp/evil":       false,
		"/home/u/.bashrc": false,
		"/var/log/syslog": false,
		"relative/path":   false,
		"/etcpasswd":      false, // not under /etc/ (no slash)
	}
	for path, want := range cases {
		if got := sensitiveWrite(path); got != want {
			t.Errorf("sensitiveWrite(%q) = %v, want %v", path, got, want)
		}
	}
}
