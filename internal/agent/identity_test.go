package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveAgentID(t *testing.T) {
	t.Run("stored id wins", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, agentIDFile), []byte("stored-id\n"), 0o600)
		id, err := resolveAgentID(dir, "legacy-id")
		if err != nil || id != "stored-id" {
			t.Fatalf("got %q, %v; want stored-id", id, err)
		}
	})

	t.Run("enrolled agent keeps legacy identity", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, tokenFile), []byte("sometoken\n"), 0o600)
		id, err := resolveAgentID(dir, "legacy-id")
		if err != nil || id != "legacy-id" {
			t.Fatalf("got %q, %v; want legacy-id", id, err)
		}
	})

	t.Run("fresh install persists and is idempotent", func(t *testing.T) {
		dir := t.TempDir()
		id1, err := resolveAgentID(dir, "legacy-id")
		if err != nil || id1 == "" {
			t.Fatalf("got %q, %v", id1, err)
		}
		// On Linux this should be the machine-id, not the legacy value —
		// but on hosts without a readable machine-id the legacy fallback is
		// acceptable; either way the answer must now be persisted and stable.
		id2, err := resolveAgentID(dir, "different-legacy")
		if err != nil || id2 != id1 {
			t.Fatalf("second resolve got %q, %v; want %q", id2, err, id1)
		}
	})
}
