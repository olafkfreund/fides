package gitstatus

import (
	"context"
	"io"
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

func TestGitLabBranchProtection(t *testing.T) {
	const apiBase = "https://10.20.30.40:8443/api/v4"
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"protected", http.StatusOK},
		{"unprotected", http.StatusNotFound},
		{"unauthorized", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				const wantURL = apiBase + "/projects/group%2Fsub%2Fproject/protected_branches/release%2Fstable"
				if r.Method != http.MethodGet || r.URL.String() != wantURL || r.Header.Get("PRIVATE-TOKEN") != "fake-token" {
					t.Errorf("expected GET %s with GitLab token, got %s %s", wantURL, r.Method, r.URL)
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
			})}
			bp, err := GetBranchProtection(t.Context(), client, ProviderGitLab, apiBase, "fake-token", Repo{Path: "group/sub/project"}, "release/stable")
			if tc.status == http.StatusUnauthorized {
				if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
					t.Fatalf("expected provider authorization error, got %+v, %v", bp, err)
				}
				return
			}
			want := BranchProtection{Branch: "release/stable", Protected: tc.status == http.StatusOK}
			if err != nil || bp != want {
				t.Fatalf("GetBranchProtection = %+v, %v, want %+v", bp, err, want)
			}
		})
	}
}
