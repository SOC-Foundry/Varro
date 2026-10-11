//go:build linux

package collect

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/soc-foundry/varro/internal/model"
)

const (
	conntrackPath   = "/proc/net/nf_conntrack"
	conntrackLegacy = "/proc/net/ip_conntrack"
	maxFlows        = 50
)

// sampleFlows reads the kernel connection-tracking table for continuous,
// byte-counted flows. Unlike the point-in-time socket list, conntrack retains
// recently-closed connections with accumulated byte counts, so short-lived
// flows between samples are still seen. Byte counts require conntrack
// accounting (net.netfilter.nf_conntrack_acct=1); without it bytes read 0 but
// the flows are still enumerated.
func (c *Collector) sampleFlows(snap *model.Snapshot) {
	f, err := os.Open(conntrackPath)
	if err != nil {
		if f, err = os.Open(conntrackLegacy); err != nil {
			return // conntrack module not loaded (no netfilter state tracking)
		}
	}
	defer f.Close()

	// Aggregate by remote ip:port, summing original-direction (out) and
	// reply-direction (in) bytes.
	type agg struct {
		proto   string
		out, in uint64
	}
	flows := map[string]*agg{}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 7 {
			continue
		}
		proto := ""
		for _, fld := range fields[:4] {
			if fld == "tcp" || fld == "udp" {
				proto = fld
				break
			}
		}
		if proto == "" {
			continue
		}
		// Parse the two "src=/dst=/sport=/dport=/bytes=" tuples. The first is
		// the original direction (local->remote); its dst is the remote peer.
		var origDst, origDport string
		var origBytes, replyBytes uint64
		seenSrc := 0
		for _, fld := range fields {
			switch {
			case strings.HasPrefix(fld, "src="):
				seenSrc++
			case strings.HasPrefix(fld, "dst=") && seenSrc == 1:
				origDst = fld[4:]
			case strings.HasPrefix(fld, "dport=") && seenSrc == 1:
				origDport = fld[6:]
			case strings.HasPrefix(fld, "bytes="):
				v := parseUint(fld[6:])
				if seenSrc == 1 {
					origBytes += v
				} else {
					replyBytes += v
				}
			}
		}
		if origDst == "" {
			continue
		}
		if ip := net.ParseIP(origDst); ip == nil || ip.IsLoopback() {
			continue
		}
		key := origDst + ":" + origDport
		a := flows[key]
		if a == nil {
			a = &agg{proto: proto}
			flows[key] = a
		}
		a.out += origBytes
		a.in += replyBytes
	}

	// conntrack enumerates flows but byte counts need nf_conntrack_acct — and on
	// hosts where the module isn't even loaded there are no conntrack flows at
	// all. Overlay per-socket tcp_info bytes from the sock_diag API (via `ss`),
	// which carries cumulative bytes for live connections. Portable, no host
	// config; fills byte counts and adds connections conntrack didn't have.
	for key, b := range ssFlows() {
		a := flows[key]
		if a == nil {
			a = &agg{proto: "tcp"}
			flows[key] = a
		}
		if a.out == 0 {
			a.out = b[0]
		}
		if a.in == 0 {
			a.in = b[1]
		}
	}

	out := make([]model.Flow, 0, len(flows))
	for remote, a := range flows {
		out = append(out, model.Flow{Proto: a.proto, Remote: remote, BytesOut: a.out, BytesIn: a.in})
	}
	// Busiest flows first; cap.
	sort.Slice(out, func(i, j int) bool {
		return out[i].BytesOut+out[i].BytesIn > out[j].BytesOut+out[j].BytesIn
	})
	if len(out) > maxFlows {
		out = out[:maxFlows]
	}
	snap.Network.Flows = out
}

// ssFlows reads per-socket cumulative byte counts from `ss -tin` (tcp, info,
// numeric — the sock_diag tcp_info). Returns remote "ip:port" -> [out, in].
// Best-effort: a missing `ss` or parse miss just yields fewer/zero entries.
func ssFlows() map[string][2]uint64 {
	out := map[string][2]uint64{}
	b, err := exec.Command("ss", "-tin").Output()
	if err != nil {
		return out
	}
	var peer string // remote of the socket whose info line follows
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			// Socket line: State Recv-Q Send-Q Local:Port Peer:Port …
			f := strings.Fields(line)
			peer = ""
			if len(f) >= 5 {
				peer = f[4]
			}
			continue
		}
		// Indented info line for the preceding socket.
		if peer == "" {
			continue
		}
		ip, port := splitPeerAddr(peer)
		if ip == "" || net.ParseIP(ip) == nil {
			continue
		}
		var bo, bi uint64
		for _, tok := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(tok, "bytes_sent:"); ok {
				bo = parseUint(v)
			} else if v, ok := strings.CutPrefix(tok, "bytes_acked:"); ok && bo == 0 {
				bo = parseUint(v)
			} else if v, ok := strings.CutPrefix(tok, "bytes_received:"); ok {
				bi = parseUint(v)
			}
		}
		if bo == 0 && bi == 0 {
			continue
		}
		key := ip + ":" + port
		cur := out[key]
		out[key] = [2]uint64{cur[0] + bo, cur[1] + bi}
	}
	return out
}

// splitPeerAddr splits ss's "ip:port" or "[v6]:port" peer field.
func splitPeerAddr(s string) (ip, port string) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", ""
	}
	ip, port = strings.Trim(s[:i], "[]"), s[i+1:]
	return ip, port
}

func parseUint(s string) uint64 {
	var n uint64
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return n
		}
		n = n*10 + uint64(ch-'0')
	}
	return n
}
