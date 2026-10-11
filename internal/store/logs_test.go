package store

import (
	"context"
	"testing"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

func TestLogsInsertAndQuery(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	// Endpoint must exist for the hostname join to populate.
	if err := s.Insert(ctx, []*model.Snapshot{testSnapshot("ep1", time.Unix(now, 0), 10)}, model.DefaultOrg); err != nil {
		t.Fatal(err)
	}
	entries := []model.LogEntry{
		{TS: now - 30, Severity: "error", Source: "sshd.service", Message: "Failed password for root"},
		{TS: now - 20, Severity: "info", Source: "cron.service", Message: "job started"},
		{TS: now - 10, Severity: "warning", Source: "kernel", Message: "temperature high"},
		{Message: ""}, // dropped: empty message
	}
	if err := s.InsertLogs(ctx, model.DefaultOrg, "ep1", entries); err != nil {
		t.Fatalf("InsertLogs: %v", err)
	}

	// All (3 non-empty), newest first, hostname joined.
	all, err := s.QueryLogs(ctx, LogQuery{Since: now - 3600, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("got %d logs, want 3", len(all))
	}
	if all[0].Message != "temperature high" {
		t.Errorf("not newest-first: %+v", all[0])
	}
	if all[0].Hostname == "" {
		t.Errorf("hostname not joined: %+v", all[0])
	}

	// Severity filter.
	errs, err := s.QueryLogs(ctx, LogQuery{Severity: "error", Since: now - 3600, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 1 || errs[0].Source != "sshd.service" {
		t.Fatalf("severity filter wrong: %+v", errs)
	}

	// Text substring filter.
	hits, err := s.QueryLogs(ctx, LogQuery{Text: "password", Since: now - 3600, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("text filter got %d, want 1", len(hits))
	}

	// Org scoping: a different org sees nothing.
	none, err := s.QueryLogs(ctx, LogQuery{OrgIDs: []string{"other-org"}, Since: now - 3600, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("org scope leaked: got %d", len(none))
	}
}
