package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestControlEnforceAllUsesEveryPage(t *testing.T) {
	var enforced []string
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer cli-token" {
			t.Errorf("Authorization = %q", got)
		}
		if r.Method == http.MethodPost {
			mu.Lock()
			enforced = append(enforced, r.URL.Path)
			mu.Unlock()
			_, _ = io.WriteString(w, "{}")
			return
		}
		if r.URL.Path != "/api/v1/controls" {
			t.Errorf("unexpected GET %s", r.URL)
		}
		switch r.URL.Query().Get("cursor") {
		case "":
			w.Header().Add("Link", "</api/v1/controls>; rel=\"self\"")
			w.Header().Add("Link", "<?cursor=opaque%2Bvalue>; rel=\"next\"")
			_, _ = io.WriteString(w, `[{"key":"FIRST"}]`)
		case "opaque+value":
			_, _ = io.WriteString(w, `[{"key":"SECOND"}]`)
		default:
			t.Errorf("unexpected cursor %q", r.URL.RawQuery)
		}
	}))
	defer server.Close()

	handleControl(CLIConfig{ServerURL: server.URL, Token: "cli-token"},
		[]string{"enforce", "--all-controls", "--all-environments"})
	want := []string{"/api/v1/controls/FIRST/enforce", "/api/v1/controls/SECOND/enforce"}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(enforced, want) {
		t.Fatalf("enforced %v, want %v", enforced, want)
	}
}

func TestCLIListRejectsCrossOrigin(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("pagination contacted a different origin")
	}))
	defer other.Close()

	for _, mode := range []string{"link", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case mode == "link":
					w.Header().Set("Link", "<"+other.URL+">; rel=\"next\"")
				case r.URL.Query().Has("cursor"):
					http.Redirect(w, r, other.URL, http.StatusFound)
					return
				default:
					w.Header().Set("Link", "<?cursor=second>; rel=\"next\"")
				}
				_, _ = io.WriteString(w, "[]")
			}))
			defer server.Close()

			body, err := getList(CLIConfig{ServerURL: server.URL, Token: "cli-token"}, "/api/v1/flows")
			if body != "" || err == nil || !strings.Contains(err.Error(), "outside") {
				t.Fatalf("getList = %q, %v", body, err)
			}
		})
	}
}

func TestFlagHistoryKeepsRequestedTotalAcrossPages(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("limit") != "500" {
			t.Errorf("unexpected page size in %s", r.URL)
		}
		switch r.URL.Query().Get("cursor") {
		case "":
			w.Header().Set("Link", "<?limit=500&cursor=second>; rel=\"next\"")
			_, _ = io.WriteString(w, "["+strings.Repeat("1,", 499)+"1]")
		case "second":
			w.Header().Set("Link", "<?limit=500&cursor=extra>; rel=\"next\"")
			_, _ = io.WriteString(w, "[2,3]")
		default:
			t.Errorf("unexpected request URL %s", r.URL)
		}
	}))
	defer server.Close()

	cfg := CLIConfig{ServerURL: server.URL}
	body, err := getListUpTo(cfg, "/api/v1/flags/history?limit=500", 501)
	if err != nil || body != "["+strings.Repeat("1,", 500)+"2]" || calls.Load() != 2 {
		t.Fatalf("expected 501 entries across two pages, got length %d, %d requests, err %v", len(body), calls.Load(), err)
	}
}
