package collect

import "testing"

// buildDNSResponse crafts a minimal DNS response for one question + answers.
// qname like "api.stripe.com"; each answer is a 4-byte A record ip.
func buildDNSResponse(qname string, as [][4]byte, withCNAME bool) []byte {
	enc := func(name string) []byte {
		var b []byte
		for _, part := range splitDots(name) {
			b = append(b, byte(len(part)))
			b = append(b, part...)
		}
		return append(b, 0)
	}
	q := enc(qname)
	ancount := len(as)
	if withCNAME {
		ancount++
	}
	hdr := []byte{
		0x12, 0x34, // id
		0x81, 0x80, // flags: QR=1, RD, RA, rcode 0
		0x00, 0x01, // qdcount
		byte(ancount >> 8), byte(ancount), // ancount
		0x00, 0x00, 0x00, 0x00,
	}
	msg := append(hdr, q...)
	msg = append(msg, 0x00, 0x01, 0x00, 0x01) // QTYPE A, QCLASS IN
	if withCNAME {
		// CNAME answer: name=ptr to qname(0x0c), type CNAME(5), rdata = encoded alias
		alias := enc("alias.example.net")
		msg = append(msg, 0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C)
		msg = append(msg, byte(len(alias)>>8), byte(len(alias)))
		msg = append(msg, alias...)
	}
	for _, a := range as {
		msg = append(msg, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04)
		msg = append(msg, a[0], a[1], a[2], a[3])
	}
	return msg
}

func splitDots(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '.' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestParseDNSResponse(t *testing.T) {
	msg := buildDNSResponse("api.stripe.com", [][4]byte{{3, 33, 1, 2}, {52, 10, 20, 30}}, false)
	qname, ips, ttl, ok := parseDNSResponse(msg)
	if !ok {
		t.Fatal("expected ok")
	}
	if qname != "api.stripe.com" {
		t.Fatalf("qname = %q", qname)
	}
	if len(ips) != 2 || ips[0] != "3.33.1.2" || ips[1] != "52.10.20.30" {
		t.Fatalf("ips = %v", ips)
	}
	if ttl != 60 {
		t.Fatalf("ttl = %d, want 60", ttl)
	}
}

func TestParseDNSResponseCNAMECollapsesToQuestion(t *testing.T) {
	// A record whose owner is a CNAME alias must still map to the queried name.
	msg := buildDNSResponse("www.github.com", [][4]byte{{140, 82, 1, 2}}, true)
	qname, ips, _, ok := parseDNSResponse(msg)
	if !ok || qname != "www.github.com" || len(ips) != 1 || ips[0] != "140.82.1.2" {
		t.Fatalf("got qname=%q ips=%v ok=%v", qname, ips, ok)
	}
}

func TestParseDNSResponseRejectsQueriesAndErrors(t *testing.T) {
	// A query (QR=0) must be rejected.
	q := buildDNSResponse("x.com", [][4]byte{{1, 1, 1, 1}}, false)
	q[2] = 0x00 // clear QR
	if _, _, _, ok := parseDNSResponse(q); ok {
		t.Fatal("query should not parse as a response")
	}
	// NXDOMAIN (rcode 3) must be rejected.
	e := buildDNSResponse("x.com", [][4]byte{{1, 1, 1, 1}}, false)
	e[3] = 0x83
	if _, _, _, ok := parseDNSResponse(e); ok {
		t.Fatal("error response should be rejected")
	}
	// Truncated input must not panic.
	if _, _, _, ok := parseDNSResponse([]byte{0x12, 0x34}); ok {
		t.Fatal("short input should fail")
	}
}
