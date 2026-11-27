package provider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetControlByKeyFollowsPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/controls" || r.URL.Query().Get("include_archived") != "true" ||
			r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "wrong request", http.StatusBadRequest)
			return
		}
		switch r.URL.Query().Get("cursor") {
		case "":
			w.Header().Set("Link", `</api/v1/controls?include_archived=true&cursor=two>; rel="next"`)
			fmt.Fprint(w, `[{"id":"1","key":"FIRST"}]`)
		case "two":
			fmt.Fprint(w, `[{"id":"2","key":"SECOND","archived":true}]`)
		default:
			http.Error(w, "wrong cursor", http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	control, err := NewClient(srv.URL, "test-token").GetControlByKey("SECOND")
	if err != nil || control == nil || control.ID != "2" || !control.Archived {
		t.Fatalf("lookup = (%+v, %v), want second page's archived control", control, err)
	}
}

func TestGetControlRejectsForeignPage(t *testing.T) {
	requests := make(chan struct{}, 1)
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests <- struct{}{}
		fmt.Fprint(w, `[]`)
	}))
	defer foreign.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", fmt.Sprintf(`<%s/controls>; rel="next"`, foreign.URL))
		fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()
	_, err := NewClient(srv.URL, "test-token").GetControlByKey("SECOND")
	if err == nil || !strings.Contains(err.Error(), "invalid control pagination link") {
		t.Fatalf("lookup error = %v, want invalid pagination link", err)
	}
	select {
	case <-requests:
		t.Fatal("client requested a foreign page")
	default:
	}
}
