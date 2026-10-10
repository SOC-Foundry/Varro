package collect

import (
	"net/netip"
	"strings"
)

// parseDNSResponse extracts the queried name and its resolved A/AAAA addresses
// from a DNS response message (the UDP payload). It returns ok=false for
// queries, errors, non-address answers, or malformed input. Pure and
// allocation-light so it can be unit-tested without a socket.
//
// We map every answer address to the question name (the hostname the client
// actually asked for), so CNAME chains collapse to the real "website" rather
// than an intermediate alias.
func parseDNSResponse(msg []byte) (qname string, ips []string, ttl uint32, ok bool) {
	if len(msg) < 12 {
		return "", nil, 0, false
	}
	flags := int(msg[2])<<8 | int(msg[3])
	if flags&0x8000 == 0 { // QR bit: 0 = query
		return "", nil, 0, false
	}
	if flags&0x000F != 0 { // RCODE != 0 (error)
		return "", nil, 0, false
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	if qd < 1 || an < 1 {
		return "", nil, 0, false
	}

	off := 12
	name, next, k := readName(msg, off)
	if !k {
		return "", nil, 0, false
	}
	qname = strings.ToLower(strings.TrimSuffix(name, "."))
	off = next + 4 // skip QTYPE + QCLASS
	for i := 1; i < qd; i++ {
		_, next, k := readName(msg, off)
		if !k {
			return "", nil, 0, false
		}
		off = next + 4
	}

	ttl = ^uint32(0)
	for i := 0; i < an; i++ {
		_, next, k := readName(msg, off)
		if !k {
			break
		}
		off = next
		if off+10 > len(msg) {
			break
		}
		typ := int(msg[off])<<8 | int(msg[off+1])
		rttl := uint32(msg[off+4])<<24 | uint32(msg[off+5])<<16 | uint32(msg[off+6])<<8 | uint32(msg[off+7])
		rdlen := int(msg[off+8])<<8 | int(msg[off+9])
		off += 10
		if rdlen < 0 || off+rdlen > len(msg) {
			break
		}
		switch {
		case typ == 1 && rdlen == 4: // A
			ips = append(ips, netip.AddrFrom4([4]byte{msg[off], msg[off+1], msg[off+2], msg[off+3]}).String())
			if rttl < ttl {
				ttl = rttl
			}
		case typ == 28 && rdlen == 16: // AAAA
			var a [16]byte
			copy(a[:], msg[off:off+16])
			ips = append(ips, netip.AddrFrom16(a).Unmap().String())
			if rttl < ttl {
				ttl = rttl
			}
		}
		off += rdlen
	}
	if len(ips) == 0 || qname == "" {
		return "", nil, 0, false
	}
	if ttl == ^uint32(0) || ttl == 0 {
		ttl = 60
	}
	return qname, ips, ttl, true
}

// readName decodes a (possibly compressed) DNS name starting at off and returns
// the dotted name plus the offset immediately after the name in the stream (for
// the first pointer encountered, that is past the 2-byte pointer). A step guard
// defends against pointer loops in malformed packets.
func readName(msg []byte, off int) (string, int, bool) {
	var labels []string
	jumped := false
	next := off
	for steps := 0; steps < 128; steps++ {
		if off < 0 || off >= len(msg) {
			return "", 0, false
		}
		b := int(msg[off])
		if b == 0 {
			off++
			if !jumped {
				next = off
			}
			return strings.Join(labels, "."), next, true
		}
		if b&0xC0 == 0xC0 { // compression pointer
			if off+1 >= len(msg) {
				return "", 0, false
			}
			ptr := ((b & 0x3F) << 8) | int(msg[off+1])
			if !jumped {
				next = off + 2
			}
			jumped = true
			off = ptr
			continue
		}
		off++
		if off+b > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[off:off+b]))
		off += b
	}
	return "", 0, false
}
