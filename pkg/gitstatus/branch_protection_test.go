package gitstatus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGithubBranchProtection(t *testing.T) {
	// Protected branch requiring 2 approvals.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/protection") {
			w.Write([]byte(`{"required_pull_request_reviews":{"required_approving_review_count":2}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	bp, err := GetBranchProtection(context.Background(), srv.Client(), "github", srv.URL, "tok", Repo{Host: "github.com", Path: "o/r"}, "main")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bp.Protected || bp.RequiredReviews != 2 {
		t.Fatalf("got %+v, want protected + 2 reviews", bp)
	}

	// 404 => unprotected (not an error).
	srv404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer srv404.Close()
	bp2, err := GetBranchProtection(context.Background(), srv404.Client(), "github", srv404.URL, "tok", Repo{Path: "o/r"}, "main")
	if err != nil || bp2.Protected {
		t.Fatalf("404 should be unprotected, got %+v err=%v", bp2, err)
	}
}
