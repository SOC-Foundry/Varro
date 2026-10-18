package collect

import "strings"

// routineWrites are files under the persistence roots that legitimately change
// on their own (resolvers, caches, clocks, CA bundles) — excluded so the
// file-write sensor stays high-signal.
var routineWrites = []string{
	"/etc/resolv.conf",
	"/etc/ld.so.cache",
	"/etc/mtab",
	"/etc/adjtime",
	"/etc/.pwd.lock",
	"/etc/machine-id",
	"/etc/hostname",
	"/etc/ssl/certs",
	"/etc/ca-certificates",
	"/etc/.updated",
	"/etc/.clean",
}

// sensitiveWrite reports whether a write to path is worth an event. The eBPF
// probe already gates to the /etc, /boot, /root roots in-kernel; this refines
// in user space by dropping routine churn and lockfiles. Kept as a pure
// function so it is unit-testable without a kernel.
func sensitiveWrite(path string) bool {
	if !strings.HasPrefix(path, "/etc/") &&
		!strings.HasPrefix(path, "/boot") &&
		!strings.HasPrefix(path, "/root") {
		return false // defensive: the kernel gate should already guarantee this
	}
	for _, n := range routineWrites {
		if path == n || strings.HasPrefix(path, n+"/") {
			return false
		}
	}
	if strings.HasSuffix(path, ".lock") || strings.HasSuffix(path, ".swp") {
		return false
	}
	return true
}
