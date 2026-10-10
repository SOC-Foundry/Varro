package collect

import "testing"

// buildClientHello crafts a minimal TLS ClientHello carrying the given SNI.
func buildClientHello(sni string) []byte {
	// Innermost: server_name extension data.
	host := []byte(sni)
	sniEntry := append([]byte{0x00, byte(len(host) >> 8), byte(len(host))}, host...) // name_type=0, len, host
	sniList := append([]byte{byte(len(sniEntry) >> 8), byte(len(sniEntry))}, sniEntry...)
	ext := append([]byte{0x00, 0x00, byte(len(sniList) >> 8), byte(len(sniList))}, sniList...) // ext_type=0, len, data
	exts := append([]byte{byte(len(ext) >> 8), byte(len(ext))}, ext...)

	body := []byte{0x03, 0x03} // client version TLS1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id len 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites: len 2 + one suite
	body = append(body, 0x01, 0x00)          // compression: len 1 + null
	body = append(body, exts...)

	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...) // ClientHello
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)                 // handshake record
	return rec
}

func TestParseSNI(t *testing.T) {
	sni, ok := parseTLSClientHelloSNI(buildClientHello("api.stripe.com"))
	if !ok || sni != "api.stripe.com" {
		t.Fatalf("got %q ok=%v", sni, ok)
	}
}

func TestParseSNIRejectsNonClientHello(t *testing.T) {
	// Application data record (type 23), not a handshake.
	if _, ok := parseTLSClientHelloSNI([]byte{23, 3, 3, 0, 1, 0}); ok {
		t.Fatal("non-handshake should be rejected")
	}
	// Truncated ClientHello must not panic.
	full := buildClientHello("example.com")
	for n := 0; n < len(full); n++ {
		parseTLSClientHelloSNI(full[:n]) // just must not panic
	}
}
