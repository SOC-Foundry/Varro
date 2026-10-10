package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

func TestAlertLifecycle(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	id, err := st.FireAlert(ctx, model.Alert{
		OrgID: "org1", Rule: "high-cpu", EndpointID: "ep1", Hostname: "h1",
		Message: "cpu high", Value: 95, StartedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// AlertOrg resolves the org for authorization.
	if org, state, _ := st.AlertOrg(ctx, id); org != "org1" || state != "firing" {
		t.Fatalf("AlertOrg = %q/%q", org, state)
	}

	// Ack a firing alert works; assignment works.
	if ok, err := st.AckAlert(ctx, id, "ann@x.com"); err != nil || !ok {
		t.Fatalf("AckAlert firing: ok=%v err=%v", ok, err)
	}
	if ok, err := st.AssignAlert(ctx, id, "bob@x.com"); err != nil || !ok {
		t.Fatalf("AssignAlert: ok=%v err=%v", ok, err)
	}

	// Verify the lifecycle fields round-trip through Alerts().
	as, err := st.Alerts(ctx, "", []string{"org1"}, 10)
	if err != nil || len(as) != 1 {
		t.Fatalf("Alerts: %v (n=%d)", err, len(as))
	}
	a := as[0]
	if a.AckBy != "ann@x.com" || a.AckAt == nil || a.Assignee != "bob@x.com" {
		t.Fatalf("lifecycle fields not persisted: %+v", a)
	}

	// Manual resolve of a firing alert works once; a second resolve is a no-op.
	if ok, err := st.ResolveAlertManual(ctx, id, "ann: false alarm"); err != nil || !ok {
		t.Fatalf("ResolveAlertManual firing: ok=%v err=%v", ok, err)
	}
	if ok, _ := st.ResolveAlertManual(ctx, id, "again"); ok {
		t.Fatal("resolving an already-resolved alert should be a no-op")
	}
	// Ack of a resolved alert is a no-op (only firing alerts are actionable).
	if ok, _ := st.AckAlert(ctx, id, "late@x.com"); ok {
		t.Fatal("acking a resolved alert should be a no-op")
	}

	// Final state reflects the resolution + note.
	as, _ = st.Alerts(ctx, "", []string{"org1"}, 10)
	if as[0].State != "resolved" || as[0].ResolvedAt == nil || as[0].Note != "ann: false alarm" {
		t.Fatalf("resolved state wrong: %+v", as[0])
	}
}
