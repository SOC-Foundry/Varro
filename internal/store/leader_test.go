package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestLeaderLease(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	// A acquires the fresh lease; B is denied while A's lease is valid.
	if ok, err := st.TryAcquireLeader(ctx, "A", time.Hour); err != nil || !ok {
		t.Fatalf("A acquire: ok=%v err=%v", ok, err)
	}
	if ok, err := st.TryAcquireLeader(ctx, "B", time.Hour); err != nil || ok {
		t.Fatalf("B should be denied while A holds: ok=%v err=%v", ok, err)
	}
	// A renews.
	if ok, _ := st.TryAcquireLeader(ctx, "A", time.Hour); !ok {
		t.Fatal("A renew failed")
	}

	// Expired lease: A holds an already-lapsed lease (negative TTL avoids
	// second-granularity flakiness); B takes over.
	if ok, _ := st.TryAcquireLeader(ctx, "A", -time.Second); !ok {
		t.Fatal("A acquire (lapsed) failed")
	}
	if ok, err := st.TryAcquireLeader(ctx, "B", time.Hour); err != nil || !ok {
		t.Fatalf("B takeover after expiry: ok=%v err=%v", ok, err)
	}
	// Now A is denied (B holds a valid lease).
	if ok, _ := st.TryAcquireLeader(ctx, "A", time.Hour); ok {
		t.Fatal("A should be denied after B took over")
	}
}
