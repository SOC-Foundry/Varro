package collect

import "strings"

// parseTLSClientHelloSNI extracts the server_name (SNI) from a TLS ClientHello,
// given the TCP payload starting at the TLS record header. It returns ok=false
// for anything that isn't a ClientHello carrying an SNI, and is bounds-checked
// throughout so malformed/partial input never panics. Pure, for unit testing
// without a socket.
//
// This recovers the real destination hostname even when the DNS lookup wasn't
// observed (cached resolution, hardcoded IP, or DNS-over-HTTPS).
func parseTLSClientHelloSNI(b []byte) (string, bool) {
	// TLS record: type(1) version(2) length(2). type 22 = handshake.
	if len(b) < 5 || b[0] != 22 {
		return "", false
	}
	recLen := int(b[3])<<8 | int(b[4])
	hs := b[5:]
	if recLen < len(hs) {
		hs = hs[:recLen]
	}
	// Handshake: type(1) length(3). type 1 = ClientHello.
	if len(hs) < 4 || hs[0] != 1 {
		return "", false
	}
	p := hs[4:]
	// ClientHello: version(2) random(32).
	if len(p) < 34 {
		return "", false
	}
	p = p[34:]
	// session_id: len(1) + bytes.
	if len(p) < 1 {
		return "", false
	}
	sidLen := int(p[0])
	if len(p) < 1+sidLen {
		return "", false
	}
	p = p[1+sidLen:]
	// cipher_suites: len(2) + bytes.
	if len(p) < 2 {
		return "", false
	}
	csLen := int(p[0])<<8 | int(p[1])
	if len(p) < 2+csLen {
		return "", false
	}
	p = p[2+csLen:]
	// compression_methods: len(1) + bytes.
	if len(p) < 1 {
		return "", false
	}
	cmLen := int(p[0])
	if len(p) < 1+cmLen {
		return "", false
	}
	p = p[1+cmLen:]
	// extensions: len(2) + bytes.
	if len(p) < 2 {
		return "", false
	}
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if extLen < len(p) {
		p = p[:extLen]
	}
	for len(p) >= 4 {
		etype := int(p[0])<<8 | int(p[1])
		elen := int(p[2])<<8 | int(p[3])
		if len(p) < 4+elen {
			return "", false
		}
		edata := p[4 : 4+elen]
		p = p[4+elen:]
		if etype != 0 { // 0 = server_name
			continue
		}
		// server_name_list: len(2), then entries of name_type(1) len(2) name.
		if len(edata) < 2 {
			return "", false
		}
		list := edata[2:]
		for len(list) >= 3 {
			nameType := list[0]
			nameLen := int(list[1])<<8 | int(list[2])
			if len(list) < 3+nameLen {
				return "", false
			}
			if nameType == 0 { // host_name
				name := strings.ToLower(strings.TrimSuffix(string(list[3:3+nameLen]), "."))
				if name == "" {
					return "", false
				}
				return name, true
			}
			list = list[3+nameLen:]
		}
	}
	return "", false
}
