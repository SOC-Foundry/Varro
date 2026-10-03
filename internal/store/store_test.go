package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

func testSnapshot(id string, ts time.Time, cpu float64) *model.Snapshot {
	return &model.Snapshot{
		AgentID:   id,
		Hostname:  "host-" + id,
		Timestamp: ts,
		Host:      model.HostInfo{OS: "linux", Platform: "arch", Arch: "amd64"},
		CPU:       model.CPUMetrics{TotalPercent: cpu, Cores: 8},
		Memory:    model.MemoryMetrics{Total: 16 << 30, Used: 8 << 30, UsedPercent: 50},
		Disks:     []model.DiskMetrics{{Mountpoint: "/", UsedPercent: 42}},
		Network:   model.NetworkMetrics{RxRate: 1000, TxRate: 500},
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestInsertAndQuery(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	snaps := []*model.Snapshot{
		testSnapshot("ep1", now.Add(-20*time.Second), 10),
		testSnapshot("ep1", now.Add(-10*time.Second), 20),
		testSnapshot("ep1", now, 30),
		testSnapshot("ep2", now, 99),
	}
	if err := s.Insert(ctx, snaps, model.DefaultOrg); err != nil {
		t.Fatal(err)
	}

	eps, err := s.Endpoints(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints, got %d", len(eps))
	}
	// Sorted by hostname: ep1 first; its latest sample has CPU 30.
	if eps[0].ID != "ep1" || eps[0].CPUPercent != 30 {
		t.Errorf("ep1 summary wrong: %+v", eps[0])
	}
	if !eps[0].Online {
		t.Error("ep1 should be online (reported just now)")
	}

	latest, err := s.Latest(ctx, "ep1")
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || latest.CPU.TotalPercent != 30 {
		t.Fatalf("latest for ep1 wrong: %+v", latest)
	}
	if none, err := s.Latest(ctx, "nope"); err != nil || none != nil {
		t.Fatalf("unknown endpoint should be nil, got %+v err %v", none, err)
	}

	points, err := s.History(ctx, "ep1", now.Add(-time.Minute), now, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 3 {
		t.Fatalf("want 3 history points, got %d", len(points))
	}
}

func TestOrgIsolation(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	orgA, err := s.CreateOrg(ctx, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	orgB, err := s.CreateOrg(ctx, "Globex")
	if err != nil {
		t.Fatal(err)
	}

	snapA := testSnapshot("ep-a", now, 10)
	snapA.Events = []model.Event{{Type: "listen_new", Message: "port 80"}}
	snapB := testSnapshot("ep-b", now, 20)
	snapB.Events = []model.Event{{Type: "listen_new", Message: "port 443"}}
	if err := s.Insert(ctx, []*model.Snapshot{snapA}, orgA.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(ctx, []*model.Snapshot{snapB}, orgB.ID); err != nil {
		t.Fatal(err)
	}

	// Endpoint scoping.
	epsA, err := s.Endpoints(ctx, []string{orgA.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(epsA) != 1 || epsA[0].ID != "ep-a" || epsA[0].OrgID != orgA.ID {
		t.Fatalf("org A sees wrong endpoints: %+v", epsA)
	}
	all, err := s.Endpoints(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("admin scope should see 2 endpoints, got %d", len(all))
	}

	// Event scoping.
	evsB, err := s.Events(ctx, "", []string{orgB.ID}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evsB) != 1 || evsB[0].Message != "port 443" {
		t.Fatalf("org B sees wrong events: %+v", evsB)
	}

	// Membership.
	if err := s.AddOrgMember(ctx, orgA.ID, "user@acme.com", ""); err != nil {
		t.Fatal(err)
	}
	orgs, err := s.UserOrgs(ctx, "user@acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(orgs) != 1 || orgs[0].ID != orgA.ID {
		t.Fatalf("membership wrong: %+v", orgs)
	}

	// Enrollment token resolves to its org.
	tok, err := s.CreateOrgToken(ctx, orgB.ID, "test", func(s string) string { return "h:" + s })
	if err != nil {
		t.Fatal(err)
	}
	gotOrg, err := s.OrgForTokenHash(ctx, "h:"+tok)
	if err != nil || gotOrg != orgB.ID {
		t.Fatalf("token resolves to %q (err %v), want %q", gotOrg, err, orgB.ID)
	}

	// Removing a member revokes their org visibility.
	if existed, err := s.RemoveOrgMember(ctx, orgA.ID, "user@acme.com"); err != nil || !existed {
		t.Fatalf("remove member: existed=%v err=%v", existed, err)
	}
	if orgs, _ := s.UserOrgs(ctx, "user@acme.com"); len(orgs) != 0 {
		t.Fatalf("member should have no orgs after removal, got %+v", orgs)
	}
	if existed, _ := s.RemoveOrgMember(ctx, orgA.ID, "user@acme.com"); existed {
		t.Fatal("second removal should report not-existed")
	}

	// Deleting an endpoint purges it and its data but leaves other orgs alone.
	if existed, err := s.DeleteEndpoint(ctx, "ep-a"); err != nil || !existed {
		t.Fatalf("delete endpoint: existed=%v err=%v", existed, err)
	}
	if all, _ := s.Endpoints(ctx, nil); len(all) != 1 || all[0].ID != "ep-b" {
		t.Fatalf("only ep-b should remain, got %+v", all)
	}
	if evs, _ := s.Events(ctx, "", nil, 10); len(evs) != 1 || evs[0].EndpointID != "ep-b" {
		t.Fatalf("ep-a events should be purged, got %+v", evs)
	}
	if existed, _ := s.DeleteEndpoint(ctx, "ep-a"); existed {
		t.Fatal("second delete should report not-existed")
	}
}

func TestPrune(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := s.Insert(ctx, []*model.Snapshot{
		testSnapshot("ep1", now.Add(-48*time.Hour), 10),
		testSnapshot("ep1", now, 20),
	}, model.DefaultOrg); err != nil {
		t.Fatal(err)
	}
	n, err := s.Prune(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("want 1 pruned row, got %d", n)
	}
	points, err := s.History(ctx, "ep1", now.Add(-72*time.Hour), now, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 1 {
		t.Fatalf("want 1 remaining point, got %d", len(points))
	}
}
