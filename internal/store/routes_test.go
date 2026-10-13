package store

import (
	"context"
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestNotifyRoutesCRUD(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	a, err := s.CreateNotifyRoute(ctx, model.NotifyRoute{
		OrgID: "org1", Type: model.RouteSlack, Target: "https://hooks.slack.com/x",
		MinSeverity: model.SevWarning, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == "" {
		t.Fatal("route has no ID")
	}
	// A disabled route + one for another org.
	if _, err := s.CreateNotifyRoute(ctx, model.NotifyRoute{
		OrgID: "org1", Type: model.RoutePagerDuty, Target: "key", MinSeverity: model.SevCritical, Enabled: false,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateNotifyRoute(ctx, model.NotifyRoute{
		OrgID: "org2", Type: model.RouteWebhook, Target: "https://x", MinSeverity: model.SevInfo, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	// org1 sees both of its routes; org2's is isolated.
	all, err := s.NotifyRoutes(ctx, "org1")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("org1 routes = %d, want 2", len(all))
	}
	// Only the enabled one is in the dispatch set.
	enabled, err := s.EnabledNotifyRoutes(ctx, "org1")
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled) != 1 || enabled[0].Type != model.RouteSlack {
		t.Fatalf("org1 enabled routes = %+v, want just the slack one", enabled)
	}

	// Cross-org delete must fail; same-org delete succeeds.
	if removed, err := s.DeleteNotifyRoute(ctx, "org2", a.ID); err != nil || removed {
		t.Fatalf("cross-org delete should fail: removed=%v err=%v", removed, err)
	}
	if removed, err := s.DeleteNotifyRoute(ctx, "org1", a.ID); err != nil || !removed {
		t.Fatalf("same-org delete should succeed: removed=%v err=%v", removed, err)
	}
	if all, _ := s.NotifyRoutes(ctx, "org1"); len(all) != 1 {
		t.Fatalf("after delete org1 has %d routes, want 1", len(all))
	}
}
