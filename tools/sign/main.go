// Command sign produces an ed25519 signature (hex) over a file. Used by the
// release workflow to sign dist/checksums.txt; agents verify the signature
// against the public key embedded in internal/agent/upgrade.go before
// self-upgrading.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	keyHex := flag.String("key", os.Getenv("VARRO_SIGNING_KEY"), "ed25519 seed, hex (or $VARRO_SIGNING_KEY)")
	in := flag.String("in", "", "file to sign")
	out := flag.String("out", "", "signature output file (hex)")
	flag.Parse()

	if *keyHex == "" || *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: sign -key <hexseed> -in <file> -out <sigfile>")
		os.Exit(2)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(*keyHex))
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintln(os.Stderr, "sign: key must be a 32-byte hex seed")
		os.Exit(1)
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		os.Exit(1)
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), data)
	if err := os.WriteFile(*out, []byte(hex.EncodeToString(sig)+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		os.Exit(1)
	}
	fmt.Printf("signed %s -> %s\n", *in, *out)
}
