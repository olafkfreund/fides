package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPListFollowsFilteredPagesWithAuth(t *testing.T) {
	t.Setenv("FIDES_API_TOKEN", "mcp-token")
	t.Setenv("FIDES_ORG_ID", "org-fixture")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mcp-token" || r.Header.Get("X-Org-Id") != "org-fixture" {
			t.Error("missing MCP auth headers")
		}
		if r.URL.Path != "/api/v1/search/artifacts" || r.URL.Query().Get("name") != "foo bar" {
			t.Errorf("unexpected request %s", r.URL)
		}
		switch r.URL.Query().Get("cursor") {
		case "":
			w.Header().Set("Link", "<?name=foo+bar>; rel=\"self\", <?name=foo+bar&cursor=opaque%2Bvalue>; rel=\"next\"")
			_, _ = io.WriteString(w, `[{"id":1}]`)
		case "opaque+value":
			w.Header().Set("Link", "</api/v1/search/artifacts?name=foo+bar&cursor=last>; rel=\"next\"")
			_, _ = io.WriteString(w, `[{"id":2}]`)
		case "last":
			_, _ = io.WriteString(w, "[]")
		default:
			t.Errorf("unexpected cursor %q", r.URL.RawQuery)
		}
	}))
	defer server.Close()

	body, err := makeListRequest(server.URL + "/api/v1/search/artifacts?name=foo+bar")
	if err != nil || string(body) != `[{"id":1},{"id":2}]` {
		t.Fatalf("makeListRequest = %s, %v", body, err)
	}
}

func TestMCPListRejectsCrossOriginAndRawGetIgnoresLink(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("pagination contacted a different origin")
	}))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "<"+strings.TrimPrefix(other.URL, "http:")+">; rel=\"next\"")
		_, _ = io.WriteString(w, "fixture")
	}))
	defer server.Close()

	body, err := makeListRequest(server.URL)
	if len(body) != 0 || err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("makeListRequest = %q, %v", body, err)
	}
	body, err = makeGetRequest(server.URL)
	if err != nil || string(body) != "fixture" {
		t.Fatalf("makeGetRequest = %q, %v", body, err)
	}
}
