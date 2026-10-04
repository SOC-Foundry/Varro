package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// releasePubKeyHex is the ed25519 public key that release checksums must be
// signed with (the private key lives only in the repo's CI secrets). An
// upgrade whose checksums.txt.sig is missing or invalid is refused.
const releasePubKeyHex = "dc3876b7f37a2ef8ef70f453b155250f96c3f7a8cfbc72d5a0f6d52ab4127985"

// verifySignature checks an ed25519 hex signature over data.
func verifySignature(pubHex string, data, hexSig []byte) bool {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(strings.TrimSpace(string(hexSig)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), data, sig)
}

// remoteConfig is what the collector's /api/v1/agent/config returns.
type remoteConfig struct {
	IntervalSeconds int      `json:"interval_seconds"`
	DesiredVersion  string   `json:"desired_version"`
	Repo            string   `json:"repo"`
	FIMPaths        []string `json:"fim_paths"`
}

// shouldUpgrade reports whether a running agent at `current` should replace
// itself with released version `desired`. Dev builds never self-replace, and
// an empty desired version means upgrades are disabled server-side.
func shouldUpgrade(current, desired string) bool {
	cur := strings.TrimPrefix(current, "v")
	des := strings.TrimPrefix(desired, "v")
	if cur == "" || des == "" || cur == "dev" || des == "dev" {
		return false
	}
	return cur != des
}

// parseChecksum extracts the sha256 for an asset from a "checksums.txt" body
// (lines of "<hex>  <name>").
func parseChecksum(checksums []byte, asset string) string {
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == asset {
			return fields[0]
		}
	}
	return ""
}

// maybeUpgrade self-upgrades to the server's desired version. On success the
// process is replaced and this never returns; on any failure it logs and the
// agent keeps running the current version.
func (a *Agent) maybeUpgrade(ctx context.Context, rc remoteConfig) {
	if !shouldUpgrade(Version, rc.DesiredVersion) || rc.Repo == "" {
		return
	}
	tag := "v" + strings.TrimPrefix(rc.DesiredVersion, "v")
	a.log.Info("self-upgrade starting", "from", Version, "to", tag, "repo", rc.Repo)
	if err := a.selfUpgrade(ctx, rc.Repo, tag); err != nil {
		a.log.Warn("self-upgrade failed, continuing on current version", "error", err)
	}
}

func (a *Agent) selfUpgrade(ctx context.Context, repo, tag string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}

	asset := "varro-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		asset += ".exe"
	}
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s", repo, tag)
	client := &http.Client{Timeout: 5 * time.Minute}

	fetch := func(url string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s returned %s", url, resp.Status)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	}

	binary, err := fetch(base + "/" + asset)
	if err != nil {
		return fmt.Errorf("download binary: %w", err)
	}
	checksums, err := fetch(base + "/checksums.txt")
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}
	sig, err := fetch(base + "/checksums.txt.sig")
	if err != nil {
		return fmt.Errorf("download signature (release may predate signing): %w", err)
	}
	if !verifySignature(releasePubKeyHex, checksums, sig) {
		return fmt.Errorf("release signature verification FAILED for %s — refusing to upgrade", tag)
	}
	want := parseChecksum(checksums, asset)
	if want == "" {
		return fmt.Errorf("no checksum for %s in release %s", asset, tag)
	}
	sum := sha256.Sum256(binary)
	if hex.EncodeToString(sum[:]) != want {
		return fmt.Errorf("checksum mismatch for %s", asset)
	}

	// Write next to the current binary (same filesystem) so the swap is
	// atomic even while the old binary is executing.
	tmp := exe + ".new"
	if err := os.WriteFile(tmp, binary, 0o755); err != nil {
		return fmt.Errorf("write new binary: %w", err)
	}
	if err := swapBinary(exe, tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("swap binary: %w", err)
	}

	// Nothing buffered may be lost across the restart.
	a.writeSpool()
	a.log.Info("self-upgrade complete, restarting", "version", tag)
	return restartSelf(exe)
}
