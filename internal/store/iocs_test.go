package store

import (
	"context"
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestIOCsCRUD(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	iocs := []model.IOC{
		{Type: model.IOCTypeIP, Value: "1.2.3.4", Source: "manual", AddedAt: 10},
		{Type: model.IOCTypeDomain, Value: "evil.example", Source: "feedA", Label: "c2", AddedAt: 20},
		{Type: model.IOCTypeHash, Value: "abc", Source: "manual", AddedAt: 30},
		{Type: "", Value: "skipme", AddedAt: 40}, // blank type → skipped
	}
	n, err := s.UpsertIOCs(ctx, model.DefaultOrg, iocs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("upserted %d, want 3 (blank skipped)", n)
	}

	// Re-upsert updates source/label without duplicating.
	if _, err := s.UpsertIOCs(ctx, model.DefaultOrg, []model.IOC{
		{Type: model.IOCTypeIP, Value: "1.2.3.4", Source: "feedB", Label: "scanner", AddedAt: 50},
	}); err != nil {
		t.Fatal(err)
	}

	counts, err := s.CountIOCs(ctx, model.DefaultOrg)
	if err != nil {
		t.Fatal(err)
	}
	if counts.IP != 1 || counts.Domain != 1 || counts.Hash != 1 {
		t.Fatalf("counts = %+v, want 1/1/1 (no dup on re-upsert)", counts)
	}

	// Type filter.
	doms, err := s.ListIOCs(ctx, model.DefaultOrg, model.IOCTypeDomain, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(doms) != 1 || doms[0].Value != "evil.example" || doms[0].Label != "c2" {
		t.Fatalf("domain list = %+v", doms)
	}

	// AllIOCs spans orgs and carries OrgID.
	if _, err := s.UpsertIOCs(ctx, "other-org", []model.IOC{
		{Type: model.IOCTypeIP, Value: "9.9.9.9", Source: "manual", AddedAt: 60},
	}); err != nil {
		t.Fatal(err)
	}
	all, err := s.AllIOCs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Fatalf("AllIOCs = %d, want 4", len(all))
	}
	foundOther := false
	for _, i := range all {
		if i.OrgID == "other-org" && i.Value == "9.9.9.9" {
			foundOther = true
		}
	}
	if !foundOther {
		t.Error("AllIOCs missing other-org IOC with OrgID set")
	}

	// Delete.
	if err := s.DeleteIOC(ctx, model.DefaultOrg, model.IOCTypeIP, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	counts, _ = s.CountIOCs(ctx, model.DefaultOrg)
	if counts.IP != 0 {
		t.Fatalf("after delete IP count = %d, want 0", counts.IP)
	}
}

func TestSTIXFeeds(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	f, err := s.AddSTIXFeed(ctx, model.STIXFeed{
		OrgID: model.DefaultOrg, URL: "https://example.com/bundle.json", Kind: "stix", Enabled: true, AddedAt: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.ID == "" {
		t.Fatal("AddSTIXFeed did not assign an ID")
	}

	feeds, err := s.ListSTIXFeeds(ctx, model.DefaultOrg)
	if err != nil {
		t.Fatal(err)
	}
	if len(feeds) != 1 || !feeds[0].Enabled || feeds[0].Kind != "stix" {
		t.Fatalf("feeds = %+v", feeds)
	}

	if err := s.UpdateSTIXFeedStatus(ctx, f.ID, 100, 42, "ok"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSTIXFeed(ctx, model.DefaultOrg, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastCount != 42 || got.LastStatus != "ok" || got.LastRun != 100 {
		t.Fatalf("status not recorded: %+v", got)
	}

	enabled, err := s.AllEnabledSTIXFeeds(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled) != 1 {
		t.Fatalf("enabled feeds = %d, want 1", len(enabled))
	}

	if err := s.DeleteSTIXFeed(ctx, model.DefaultOrg, f.ID); err != nil {
		t.Fatal(err)
	}
	feeds, _ = s.ListSTIXFeeds(ctx, model.DefaultOrg)
	if len(feeds) != 0 {
		t.Fatalf("after delete, feeds = %d, want 0", len(feeds))
	}
}
