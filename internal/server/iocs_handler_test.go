package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func iocReq(method, target, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer master-secret")
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("id", "default")
	return r
}

func TestIOCHandlersCRUD(t *testing.T) {
	srv, st := newTestServer(t)

	// create
	w := httptest.NewRecorder()
	srv.handleIOCCreate(w, iocReq("POST", "/api/v1/orgs/default/iocs", `{"type":"ip","value":"203.0.113.9","label":"c2"}`))
	if w.Code != 200 {
		t.Fatalf("create status %d: %s", w.Code, w.Body.String())
	}

	// invalid value rejected
	w = httptest.NewRecorder()
	srv.handleIOCCreate(w, iocReq("POST", "/api/v1/orgs/default/iocs", `{"type":"ip","value":"not-an-ip"}`))
	if w.Code != 400 {
		t.Errorf("invalid ip should be 400, got %d", w.Code)
	}

	// list shows the indicator + counts
	w = httptest.NewRecorder()
	srv.handleIOCList(w, iocReq("GET", "/api/v1/orgs/default/iocs", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "203.0.113.9") {
		t.Fatalf("list status %d: %s", w.Code, w.Body.String())
	}

	// delete by query params
	w = httptest.NewRecorder()
	srv.handleIOCDelete(w, iocReq("DELETE", "/api/v1/orgs/default/iocs?type=ip&value=203.0.113.9", ""))
	if w.Code != 200 {
		t.Fatalf("delete status %d: %s", w.Code, w.Body.String())
	}
	if c, _ := st.CountIOCs(context.Background(), "default"); c.IP != 0 {
		t.Errorf("IP count after delete = %d, want 0", c.IP)
	}
}

func TestIOCHandlerUnauthenticated(t *testing.T) {
	srv, _ := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/orgs/default/iocs", nil) // no Authorization
	r.SetPathValue("id", "default")
	srv.handleIOCList(w, r)
	if w.Code == 200 {
		t.Errorf("unauthenticated IOC list must not be 200, got %d", w.Code)
	}
}

func TestSTIXIngestHandler(t *testing.T) {
	srv, st := newTestServer(t)
	bundle := `{"type":"bundle","objects":[
	  {"type":"indicator","pattern":"[domain-name:value = 'evil.example']"},
	  {"type":"ipv4-addr","value":"198.51.100.7"}
	]}`
	w := httptest.NewRecorder()
	srv.handleSTIXIngest(w, iocReq("POST", "/api/v1/orgs/default/stix/ingest", bundle))
	if w.Code != 200 {
		t.Fatalf("ingest status %d: %s", w.Code, w.Body.String())
	}
	c, _ := st.CountIOCs(context.Background(), "default")
	if c.Domain != 1 || c.IP != 1 {
		t.Errorf("after ingest counts = %+v, want domain=1 ip=1", c)
	}

	// empty/garbage bundle → 400 (no indicators)
	w = httptest.NewRecorder()
	srv.handleSTIXIngest(w, iocReq("POST", "/api/v1/orgs/default/stix/ingest", `{"objects":[]}`))
	if w.Code != 400 {
		t.Errorf("empty bundle should be 400, got %d", w.Code)
	}
}

func TestSLOHandlers(t *testing.T) {
	srv, _ := newTestServer(t)
	// create
	w := httptest.NewRecorder()
	srv.handleSLOCreate(w, iocReq("POST", "/api/v1/orgs/default/slos", `{"service":"api","target":0.99,"window_minutes":60}`))
	if w.Code != 200 {
		t.Fatalf("create SLO: %d %s", w.Code, w.Body.String())
	}
	// invalid target rejected
	w = httptest.NewRecorder()
	srv.handleSLOCreate(w, iocReq("POST", "/api/v1/orgs/default/slos", `{"service":"api","target":1.5}`))
	if w.Code != 400 {
		t.Errorf("target 1.5 should be 400, got %d", w.Code)
	}
	// list (read-scoped) — no traces yet → no-data status
	w = httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/slos", nil)
	r.Header.Set("Authorization", "Bearer master-secret")
	srv.handleSLOList(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"api"`) || !strings.Contains(w.Body.String(), "no-data") {
		t.Fatalf("list SLO: %d %s", w.Code, w.Body.String())
	}
	// delete
	w = httptest.NewRecorder()
	dr := iocReq("DELETE", "/api/v1/orgs/default/slos/api", "")
	dr.SetPathValue("service", "api")
	srv.handleSLODelete(w, dr)
	if w.Code != 200 {
		t.Fatalf("delete SLO: %d %s", w.Code, w.Body.String())
	}
}

func TestSTIXFeedCreateValidatesURL(t *testing.T) {
	srv, _ := newTestServer(t)
	// non-http scheme rejected
	w := httptest.NewRecorder()
	srv.handleSTIXFeedCreate(w, iocReq("POST", "/api/v1/orgs/default/stix/feeds", `{"url":"file:///etc/passwd","kind":"stix"}`))
	if w.Code != 400 {
		t.Errorf("file:// URL should be rejected 400, got %d", w.Code)
	}
}
