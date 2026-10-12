package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestCICDIngest(t *testing.T) {
	srv, st := newTestServer(t)

	body := `{"event":"deploy","service":"checkout","status":"success","ref":"main","version":"v1.2.3","url":"https://ci/run/9"}`
	r := httptest.NewRequest("POST", "/api/v1/cicd", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer master-secret")
	w := httptest.NewRecorder()
	srv.handleCICD(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}

	evs, err := st.Events(context.Background(), "", nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	e := evs[0]
	if e.Type != model.EventCICD {
		t.Errorf("type = %q, want %q", e.Type, model.EventCICD)
	}
	// Message should read like "deploy checkout → success (v1.2.3 @main) https://ci/run/9".
	for _, want := range []string{"deploy checkout", "success", "v1.2.3", "@main", "https://ci/run/9"} {
		if !strings.Contains(e.Message, want) {
			t.Errorf("message %q missing %q", e.Message, want)
		}
	}

	// Unauthorized without a token.
	r2 := httptest.NewRequest("POST", "/api/v1/cicd", strings.NewReader(body))
	w2 := httptest.NewRecorder()
	srv.handleCICD(w2, r2)
	if w2.Code != 401 {
		t.Fatalf("no-token status = %d, want 401", w2.Code)
	}
}
