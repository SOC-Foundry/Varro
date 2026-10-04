package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/soc-foundry/varro/internal/model"
)

const (
	maxFIMFiles    = 500       // total files tracked across all watch paths
	maxFIMFileSize = 64 << 20  // files larger than this are fingerprinted only
	maxFIMEvents   = 20        // per sample
)

type fimEntry struct {
	fingerprint string // size:mtime
	hash        string // sha256, "" when too large to hash
}

// SetFIMPaths replaces the server-pushed watchlist. Changing the list resets
// the baseline (new paths report silently on first scan).
func (c *Collector) SetFIMPaths(paths []string) {
	c.fimMu.Lock()
	defer c.fimMu.Unlock()
	sort.Strings(paths)
	if fmt.Sprint(paths) == fmt.Sprint(c.fimPaths) {
		return
	}
	c.fimPaths = paths
	c.fimState = nil
}

// sampleFIM diffs the watched files every sample. Fingerprints (size+mtime)
// gate hashing so unchanged files cost one stat each.
func (c *Collector) sampleFIM(snap *model.Snapshot) {
	c.fimMu.Lock()
	paths := c.fimPaths
	c.fimMu.Unlock()
	if len(paths) == 0 {
		return
	}

	current := map[string]fimEntry{}
	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			c.fimVisit(root, info, current)
			continue
		}
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d == nil || d.IsDir() {
				return nil
			}
			if len(current) >= maxFIMFiles {
				return filepath.SkipAll
			}
			if fi, err := d.Info(); err == nil {
				c.fimVisit(path, fi, current)
			}
			return nil
		})
		if len(current) >= maxFIMFiles {
			break
		}
	}

	if c.fimState != nil {
		n := 0
		emit := func(msg string) {
			if n < maxFIMEvents {
				snap.Events = append(snap.Events, model.Event{Type: model.EventFIMChange, Message: msg})
				n++
			}
		}
		for path, cur := range current {
			prev, ok := c.fimState[path]
			switch {
			case !ok:
				emit("watched file created: " + path + " (sha256 " + short(cur.hash) + ")")
			case prev.hash != cur.hash || (cur.hash == "" && prev.fingerprint != cur.fingerprint):
				emit("watched file modified: " + path + " (sha256 " + short(prev.hash) + " -> " + short(cur.hash) + ")")
			}
		}
		for path := range c.fimState {
			if _, ok := current[path]; !ok {
				emit("watched file removed: " + path)
			}
		}
	}
	c.fimState = current
}

// fimVisit records one file, hashing only when the fingerprint changed since
// the previous scan.
func (c *Collector) fimVisit(path string, info os.FileInfo, current map[string]fimEntry) {
	fp := fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
	if prev, ok := c.fimState[path]; ok && prev.fingerprint == fp {
		current[path] = prev
		return
	}
	entry := fimEntry{fingerprint: fp}
	if info.Size() <= maxFIMFileSize {
		if f, err := os.Open(path); err == nil {
			h := sha256.New()
			if _, err := io.Copy(h, f); err == nil {
				entry.hash = hex.EncodeToString(h.Sum(nil))
			}
			f.Close()
		}
	}
	current[path] = entry
}

func short(hash string) string {
	if hash == "" {
		return "unhashed"
	}
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
