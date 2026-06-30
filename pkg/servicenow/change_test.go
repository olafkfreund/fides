package servicenow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryChangeRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/now/table/change_request" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("sysparm_query") != "number=CHG0030192" {
			t.Errorf("query = %s", r.URL.RawQuery)
		}
		w.Write([]byte(`{"result":[{"number":"CHG0030192","state":"-1","approval":"approved","risk":"low","on_hold":"false"}]}`))
	}))
	defer srv.Close()

	c := testClient(srv.URL, AuthBasic, srv.Client())
	cr, found, err := QueryChangeRequest(context.Background(), c, "number=CHG0030192")
	if err != nil || !found {
		t.Fatalf("expected a change request, found=%v err=%v", found, err)
	}
	if cr["number"] != "CHG0030192" {
		t.Fatalf("wrong CR: %+v", cr)
	}
}

func TestQueryChangeRequestNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":[]}`))
	}))
	defer srv.Close()
	c := testClient(srv.URL, AuthBasic, srv.Client())
	_, found, err := QueryChangeRequest(context.Background(), c, "number=NOPE")
	if err != nil || found {
		t.Fatalf("expected not found, got found=%v err=%v", found, err)
	}
}

func TestNormalizeChange(t *testing.T) {
	cr := map[string]any{
		"number":   "CHG0030192",
		"state":    "-1", // implement
		"approval": "approved",
		"risk":     "moderate",
		"on_hold":  "false",
	}
	n := NormalizeChange(cr)
	if n["state"] != "implement" {
		t.Errorf("state should map to label 'implement', got %v", n["state"])
	}
	if n["on_hold"] != false {
		t.Errorf("on_hold should be a bool false, got %v (%T)", n["on_hold"], n["on_hold"])
	}
	if n["approval"] != "approved" {
		t.Errorf("approval = %v", n["approval"])
	}

	// A display-value state passes through unchanged.
	if NormalizeChange(map[string]any{"state": "Implement"})["state"] != "Implement" {
		t.Errorf("display-value state should pass through")
	}
}
