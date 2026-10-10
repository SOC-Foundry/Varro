package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestShouldUpgrade(t *testing.T) {
	cases := []struct {
		current, desired string
		want             bool
	}{
		{"v0.4.1", "v0.4.2", true},
		{"0.4.1", "v0.4.2", true},  // bare current vs tagged desired
		{"v0.4.2", "0.4.2", false}, // same version, mixed prefixes
		{"v0.4.2", "v0.4.1", true}, // rollback is a valid upgrade direction
		{"dev", "v0.4.2", false},   // dev builds never self-replace
		{"v0.4.1", "dev", false},   // never "upgrade" to a dev version
		{"v0.4.1", "", false},      // upgrades disabled server-side
		{"", "v0.4.2", false},
	}
	for _, c := range cases {
		if got := shouldUpgrade(c.current, c.desired); got != c.want {
			t.Errorf("shouldUpgrade(%q, %q) = %v, want %v", c.current, c.desired, got, c.want)
		}
	}
}

func TestVerifySignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("abc123  varro-linux-amd64\n")
	sig := []byte(hex.EncodeToString(ed25519.Sign(priv, data)) + "\n")
	pubHex := hex.EncodeToString(pub)

	if !verifySignature(pubHex, data, sig) {
		t.Error("valid signature should verify")
	}
	if verifySignature(pubHex, []byte("tampered"), sig) {
		t.Error("tampered data must not verify")
	}
	if verifySignature(releasePubKeyHex, data, sig) {
		t.Error("signature from a different key must not verify against the release key")
	}
	if verifySignature(pubHex, data, []byte("not-hex")) {
		t.Error("garbage signature must not verify")
	}
}

func TestParseChecksum(t *testing.T) {
	body := []byte(`abc123  varro-linux-amd64
def456  varro-linux-arm64
789fed  checksums-decoy varro-linux-amd64
`)
	if got := parseChecksum(body, "varro-linux-amd64"); got != "abc123" {
		t.Errorf("got %q, want abc123", got)
	}
	if got := parseChecksum(body, "varro-darwin-arm64"); got != "" {
		t.Errorf("missing asset should return empty, got %q", got)
	}
}
