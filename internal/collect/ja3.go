package collect

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

// parseClientHelloJA3 computes the JA3 fingerprint of a TLS ClientHello, given the
// TCP payload starting at the TLS record header. JA3 is the MD5 of
//
//	SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
//
// where each list is '-'-joined decimal values with GREASE (RFC 8701) excluded.
// It also returns the SNI it finds. Bounds-checked throughout; returns ok=false
// for anything that isn't a parseable ClientHello. Pure, for unit testing.
func parseClientHelloJA3(b []byte) (ja3hash, ja3 string, sni string, ok bool) {
	if len(b) < 5 || b[0] != 22 { // handshake record
		return "", "", "", false
	}
	recLen := int(b[3])<<8 | int(b[4])
	hs := b[5:]
	if recLen < len(hs) {
		hs = hs[:recLen]
	}
	if len(hs) < 4 || hs[0] != 1 { // ClientHello
		return "", "", "", false
	}
	p := hs[4:]
	if len(p) < 2 {
		return "", "", "", false
	}
	version := int(p[0])<<8 | int(p[1])
	if len(p) < 34 {
		return "", "", "", false
	}
	p = p[34:] // skip version(2)+random(32)
	// session_id
	if len(p) < 1 || len(p) < 1+int(p[0]) {
		return "", "", "", false
	}
	p = p[1+int(p[0]):]
	// cipher_suites
	if len(p) < 2 {
		return "", "", "", false
	}
	csLen := int(p[0])<<8 | int(p[1])
	if len(p) < 2+csLen {
		return "", "", "", false
	}
	var ciphers []string
	for i := 2; i+1 < 2+csLen; i += 2 {
		v := int(p[i])<<8 | int(p[i+1])
		if !greaseJA3(v) {
			ciphers = append(ciphers, strconv.Itoa(v))
		}
	}
	p = p[2+csLen:]
	// compression_methods
	if len(p) < 1 || len(p) < 1+int(p[0]) {
		return "", "", "", false
	}
	p = p[1+int(p[0]):]
	// extensions
	if len(p) < 2 {
		return "", "", "", false
	}
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if extLen < len(p) {
		p = p[:extLen]
	}
	var exts, curves, formats []string
	for len(p) >= 4 {
		etype := int(p[0])<<8 | int(p[1])
		elen := int(p[2])<<8 | int(p[3])
		if len(p) < 4+elen {
			break
		}
		edata := p[4 : 4+elen]
		p = p[4+elen:]
		if !greaseJA3(etype) {
			exts = append(exts, strconv.Itoa(etype))
		}
		switch etype {
		case 0: // server_name
			if s, okk := sniFromExt(edata); okk {
				sni = s
			}
		case 10: // supported_groups (elliptic curves)
			if len(edata) >= 2 {
				n := int(edata[0])<<8 | int(edata[1])
				for i := 2; i+1 < 2+n && i+1 < len(edata); i += 2 {
					v := int(edata[i])<<8 | int(edata[i+1])
					if !greaseJA3(v) {
						curves = append(curves, strconv.Itoa(v))
					}
				}
			}
		case 11: // ec_point_formats
			if len(edata) >= 1 {
				n := int(edata[0])
				for i := 1; i < 1+n && i < len(edata); i++ {
					formats = append(formats, strconv.Itoa(int(edata[i])))
				}
			}
		}
	}
	ja3 = strconv.Itoa(version) + "," +
		strings.Join(ciphers, "-") + "," +
		strings.Join(exts, "-") + "," +
		strings.Join(curves, "-") + "," +
		strings.Join(formats, "-")
	sum := md5.Sum([]byte(ja3))
	return hex.EncodeToString(sum[:]), ja3, sni, true
}

// greaseJA3 reports whether a 16-bit value is a GREASE placeholder (RFC 8701):
// the 16 values 0x0a0a, 0x1a1a, … 0xfafa, which must be excluded from JA3.
func greaseJA3(v int) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

// sniFromExt extracts host_name from a server_name extension body.
func sniFromExt(edata []byte) (string, bool) {
	if len(edata) < 2 {
		return "", false
	}
	list := edata[2:]
	for len(list) >= 3 {
		nameLen := int(list[1])<<8 | int(list[2])
		if len(list) < 3+nameLen {
			return "", false
		}
		if list[0] == 0 { // host_name
			name := strings.ToLower(strings.TrimSuffix(string(list[3:3+nameLen]), "."))
			if name != "" {
				return name, true
			}
		}
		list = list[3+nameLen:]
	}
	return "", false
}
