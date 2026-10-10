//go:build linux

package collect

import (
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// DNSWatcher passively observes DNS responses and TLS ClientHello SNI on the
// host and maintains an IP -> domain cache, so topology can label external talk
// with the real hostname (e.g. "api.stripe.com") instead of a useless
// reverse-DNS PTR.
//
// It uses AF_PACKET SOCK_DGRAM sockets with tiny kernel cBPF filters (UDP for
// DNS; TCP dst-port 443 for SNI), then parses the answer in user space. Local
// observation only — nothing leaves the host. Needs CAP_NET_RAW (the agent runs
// as root); degrades to "unavailable" otherwise. DNS gives the forward lookup;
// SNI fills gaps where the lookup was cached, hardcoded, or over DoH.
type DNSWatcher struct {
	fds    []int
	mu     sync.RWMutex
	cache  map[string]dnsEntry
	closed bool
}

type dnsEntry struct {
	domain string
	expiry time.Time
}

const (
	dnsCacheMax = 8192
	// Keep a resolution well past its record TTL: a connection to the IP often
	// outlives the DNS TTL, and we only need a human-facing label.
	dnsMinHold = 30 * time.Minute
	sniHold    = 30 * time.Minute
)

// openPacketSocket opens an AF_PACKET SOCK_DGRAM socket (all interfaces,
// including loopback) with the given classic-BPF filter attached in-kernel.
func openPacketSocket(filter []unix.SockFilter) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_IP)))
	if err != nil {
		return -1, fmt.Errorf("open AF_PACKET socket: %w", err)
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("attach BPF filter: %w", err)
	}
	return fd, nil
}

// StartDNSWatch opens the capture sockets and begins reading in goroutines.
func StartDNSWatch() (*DNSWatcher, error) {
	// On a SOCK_DGRAM packet the data starts at the IP header; byte 9 is the
	// protocol. Pass only UDP (17) for DNS so the socket isn't a firehose.
	dnsFilter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 9},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: 17},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0x40000},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}
	// TCP (6) with destination port 443. BPF_MSH loads 4*(IHL) into X so the
	// halfword at [x+2] is the TCP destination port.
	sniFilter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 9},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 4, K: 6},
		{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 0},
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 2},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: 443},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0x40000},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}

	dnsFD, err := openPacketSocket(dnsFilter)
	if err != nil {
		return nil, err
	}
	w := &DNSWatcher{fds: []int{dnsFD}, cache: make(map[string]dnsEntry)}

	// SNI capture is a bonus; if its socket fails, keep DNS working.
	if sniFD, err := openPacketSocket(sniFilter); err == nil {
		w.fds = append(w.fds, sniFD)
		go w.run(sniFD, w.handleTCP)
	}
	go w.run(dnsFD, w.handleUDP)
	return w, nil
}

func (w *DNSWatcher) run(fd int, handle func([]byte)) {
	buf := make([]byte, 65535)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			w.mu.RLock()
			closed := w.closed
			w.mu.RUnlock()
			if closed {
				return
			}
			continue
		}
		handle(buf[:n])
	}
}

// handleUDP parses an IPv4/UDP packet and, if it's a DNS response (src port 53),
// records each resolved address under the queried name.
func (w *DNSWatcher) handleUDP(p []byte) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return
	}
	ihl := int(p[0]&0x0F) * 4
	if ihl < 20 || len(p) < ihl+8 || p[9] != 17 {
		return
	}
	udp := p[ihl:]
	if int(udp[0])<<8|int(udp[1]) != 53 { // DNS source port
		return
	}
	qname, ips, ttl, ok := parseDNSResponse(udp[8:])
	if !ok {
		return
	}
	hold := time.Duration(ttl) * time.Second
	if hold < dnsMinHold {
		hold = dnsMinHold
	}
	exp := time.Now().Add(hold)
	w.mu.Lock()
	w.ensureRoomLocked()
	for _, ip := range ips {
		w.cache[ip] = dnsEntry{domain: qname, expiry: exp}
	}
	w.mu.Unlock()
}

// handleTCP parses an IPv4/TCP :443 packet and, if it carries a ClientHello,
// records the destination server IP under its SNI hostname.
func (w *DNSWatcher) handleTCP(p []byte) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return
	}
	ihl := int(p[0]&0x0F) * 4
	if ihl < 20 || p[9] != 6 || len(p) < ihl+20 {
		return
	}
	dstIP := net.IP(p[16:20]).String()
	tcp := p[ihl:]
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) < dataOff {
		return
	}
	sni, ok := parseTLSClientHelloSNI(tcp[dataOff:])
	if !ok {
		return
	}
	w.mu.Lock()
	w.ensureRoomLocked()
	w.cache[dstIP] = dnsEntry{domain: sni, expiry: time.Now().Add(sniHold)}
	w.mu.Unlock()
}

// Lookup returns the most recently observed domain for an IP, or "" if unknown
// or expired.
func (w *DNSWatcher) Lookup(ip string) string {
	w.mu.RLock()
	e, ok := w.cache[ip]
	w.mu.RUnlock()
	if !ok || time.Now().After(e.expiry) {
		return ""
	}
	return e.domain
}

// ensureRoomLocked bounds cache memory; caller holds the write lock.
func (w *DNSWatcher) ensureRoomLocked() {
	if len(w.cache) < dnsCacheMax {
		return
	}
	now := time.Now()
	for ip, e := range w.cache {
		if now.After(e.expiry) {
			delete(w.cache, ip)
		}
	}
	if len(w.cache) >= dnsCacheMax { // still full of live entries: drop a chunk
		n := 0
		for ip := range w.cache {
			delete(w.cache, ip)
			if n++; n >= dnsCacheMax/4 {
				break
			}
		}
	}
}

func (w *DNSWatcher) Close() error {
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	var err error
	for _, fd := range w.fds {
		if e := unix.Close(fd); e != nil {
			err = e
		}
	}
	return err
}

// htons converts a uint16 to network byte order for the AF_PACKET protocol arg.
func htons(v uint16) uint16 { return (v<<8)&0xff00 | (v>>8)&0x00ff }
