//go:build linux

package collect

import (
	"bufio"
	"net"
	"os"
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
		proto    string
		out, in  uint64
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
