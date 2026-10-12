package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

func TestServiceErrorRateAlert(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	now := time.Now().Unix()

	// 25 root requests for "api", 5 errors = 20% (> 5% threshold).
	var spans []model.OTLPSpan
	for i := 0; i < 25; i++ {
		status := "ok"
		if i < 5 {
			status = "error"
		}
		spans = append(spans, model.OTLPSpan{
			TraceID: fmt.Sprintf("t%d", i), SpanID: fmt.Sprintf("s%d", i),
			Service: "api", DurNs: 5_000_000, Status: status, TS: now,
		})
	}
	if err := st.InsertOTLPSpans(ctx, model.DefaultOrg, spans); err != nil {
		t.Fatal(err)
	}

	srv.evaluateServiceAlerts(ctx)

	id, err := st.OpenAlert(ctx, "service-error-rate", "svc/"+model.DefaultOrg+"/api")
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("expected a service-error-rate alert to be firing for api (20% > 5%)")
	}
}

func TestLogErrorCountAndBurstAlert(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	now := time.Now().Unix()

	if err := st.Insert(ctx, []*model.Snapshot{{AgentID: "ep1", Hostname: "ep1", Timestamp: time.Unix(now, 0)}}, model.DefaultOrg); err != nil {
		t.Fatal(err)
	}
	var entries []model.LogEntry
	for i := 0; i < 60; i++ { // 60 error lines > 50 threshold
		entries = append(entries, model.LogEntry{TS: now, Severity: "error", Message: fmt.Sprintf("boom %d", i)})
	}
	entries = append(entries, model.LogEntry{TS: now, Severity: "info", Message: "fine"}) // not counted
	if err := st.InsertLogs(ctx, model.DefaultOrg, "ep1", entries); err != nil {
		t.Fatal(err)
	}

	if n, err := st.LogErrorCount(ctx, "ep1", now-300); err != nil || n != 60 {
		t.Fatalf("LogErrorCount = %d (err %v), want 60", n, err)
	}

	srv.evaluateLogAlerts(ctx)
	id, err := st.OpenAlert(ctx, "log-error-burst", "ep1")
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("expected a log-error-burst alert firing for ep1 (60 > 50)")
	}
}
