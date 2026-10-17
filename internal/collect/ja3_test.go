package collect

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
)

// buildHelloJA3 constructs a minimal TLS ClientHello record from the given
// fields so the JA3 output is hand-verifiable.
func buildHelloJA3(version int, ciphers []int, exts []extension) []byte {
	be16 := func(v int) []byte { return []byte{byte(v >> 8), byte(v)} }

	var body []byte
	body = append(body, be16(version)...)    // client version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session_id len 0
	// cipher_suites
	var cs []byte
	for _, c := range ciphers {
		cs = append(cs, be16(c)...)
	}
	body = append(body, be16(len(cs))...)
	body = append(body, cs...)
	// compression_methods: 1 method (null)
	body = append(body, 1, 0)
	// extensions
	var ext []byte
	for _, e := range exts {
		ext = append(ext, be16(e.typ)...)
		ext = append(ext, be16(len(e.data))...)
		ext = append(ext, e.data...)
	}
	body = append(body, be16(len(ext))...)
	body = append(body, ext...)

	// handshake header: type(1)=1 + length(3)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	// record header: type(1)=22 version(2) length(2)
	rec := append([]byte{22, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	return rec
}

type extension struct {
	typ  int
	data []byte
}

func TestParseClientHelloJA3(t *testing.T) {
	be16 := func(v int) []byte { return []byte{byte(v >> 8), byte(v)} }
	// supported_groups (ext 10): list len + two curves (one GREASE, dropped).
	groups := append(be16(4), append(be16(0x0a0a), be16(29)...)...) // GREASE 0x0a0a + x25519(29)
	// ec_point_formats (ext 11): 1 format (0 = uncompressed).
	formats := []byte{1, 0}
	// server_name (ext 0) for "example.com"
	host := "example.com"
	snl := append(be16(len(host)+3), append([]byte{0}, append(be16(len(host)), []byte(host)...)...)...)

	hello := buildHelloJA3(771, // TLS 1.2
		[]int{0x1301, 0x0a0a, 0xc02b}, // AES_128_GCM, GREASE(dropped), ECDHE
		[]extension{
			{0x0a0a, nil}, // GREASE extension (dropped)
			{0, snl},      // SNI
			{10, groups},
			{11, formats},
		})

	hash, ja3, sni, ok := parseClientHelloJA3(hello)
	if !ok {
		t.Fatal("expected ok")
	}
	if sni != "example.com" {
		t.Errorf("sni = %q, want example.com", sni)
	}
	// Hand-computed: version 771; ciphers 4865-49195 (GREASE removed);
	// extensions 0-10-11 (GREASE removed); curves 29 (GREASE removed); formats 0.
	wantJA3 := "771,4865-49195,0-10-11,29,0"
	if ja3 != wantJA3 {
		t.Fatalf("ja3 string = %q, want %q", ja3, wantJA3)
	}
	sum := md5.Sum([]byte(wantJA3))
	if hash != hex.EncodeToString(sum[:]) {
		t.Errorf("hash = %q, want md5(%q)", hash, wantJA3)
	}
}

func TestGreaseJA3(t *testing.T) {
	for _, g := range []int{0x0a0a, 0x1a1a, 0x2a2a, 0xfafa} {
		if !greaseJA3(g) {
			t.Errorf("%#x should be GREASE", g)
		}
	}
	for _, n := range []int{0x1301, 0xc02b, 29, 0, 0x0a0b, 0x1a2a} {
		if greaseJA3(n) {
			t.Errorf("%#x should not be GREASE", n)
		}
	}
}

func TestParseClientHelloJA3Garbage(t *testing.T) {
	if _, _, _, ok := parseClientHelloJA3([]byte{0, 1, 2}); ok {
		t.Error("garbage should not parse")
	}
	if _, _, _, ok := parseClientHelloJA3(nil); ok {
		t.Error("nil should not parse")
	}
}
