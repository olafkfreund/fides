package gitstatus

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sigstoreBundleJSON(t *testing.T, statement map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"dsseEnvelope": map[string]any{
			"payload":     base64.StdEncoding.EncodeToString(raw),
			"payloadType": "application/vnd.in-toto+json",
		},
	}
	b, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return string(b)
}

const testDigest = "76c34666f719ef14bd2b124a7db51e9c05e4db2e12a84800296d559064eebe2c"

func TestFetchGitHubAttestations(t *testing.T) {
	bundleJSON := sigstoreBundleJSON(t, map[string]any{
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject":       []map[string]any{{"name": "app", "digest": map[string]string{"sha256": testDigest}}},
	})

	var gotListPath, gotAuth, gotAccept string
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	bundlePath := "/repos/acme/widgets/attestations/sha256:" + testDigest + "/bundle"
	mux.HandleFunc("/repos/acme/widgets/attestations/", func(w http.ResponseWriter, r *http.Request) {
		gotListPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		fmt.Fprintf(w, `{"attestations":[{"repository_id":1,"bundle_url":%q}]}`, srv.URL+bundlePath)
	})
	mux.HandleFunc(bundlePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer tok123" {
			t.Error("expected an authenticated GET to the GitHub bundle endpoint")
		}
		w.Write([]byte(bundleJSON))
	})

	statements, err := FetchAttestations(context.Background(), srv.Client(), ProviderGitHub, srv.URL, "tok123", Repo{Host: "github.com", Path: "acme/widgets"}, testDigest)
	if err != nil {
		t.Fatalf("FetchAttestations: %v", err)
	}
	if len(statements) != 1 {
		t.Fatalf("got %d statements, want 1", len(statements))
	}
	if statements[0].PredicateType != "https://slsa.dev/provenance/v1" {
		t.Errorf("PredicateType = %q", statements[0].PredicateType)
	}
	if statements[0].SourceURL != srv.URL+bundlePath {
		t.Errorf("SourceURL = %q, want %q", statements[0].SourceURL, srv.URL+bundlePath)
	}
	if !strings.Contains(gotListPath, "/repos/acme/widgets/attestations/sha256:"+testDigest) {
		t.Errorf("unexpected list path: %s", gotListPath)
	}
	if gotAuth != "Bearer tok123" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotAccept != "application/vnd.github+json" {
		t.Errorf("Accept = %q", gotAccept)
	}
}

func TestFetchGitLabAttestations(t *testing.T) {
	bundleJSON := sigstoreBundleJSON(t, map[string]any{
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject":       []map[string]any{{"name": "app", "digest": map[string]string{"sha256": testDigest}}},
	})

	var gotListPath, gotToken string
	const bundlePath = "/projects/group%2Fproject/attestations/1/download"
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.EscapedPath() == bundlePath:
			if r.Method != http.MethodGet || r.Header.Get("PRIVATE-TOKEN") != "glpat-xyz" {
				t.Error("expected an authenticated GET to the GitLab bundle endpoint")
			}
			w.Write([]byte(bundleJSON))
		default:
			gotListPath = r.RequestURI
			gotToken = r.Header.Get("PRIVATE-TOKEN")
			fmt.Fprintf(w, `[{"iid":1,"predicate_type":"https://slsa.dev/provenance/v1","download_url":%q}]`, srv.URL+bundlePath)
		}
	}))
	defer srv.Close()

	statements, err := FetchAttestations(context.Background(), srv.Client(), ProviderGitLab, srv.URL, "glpat-xyz", Repo{Host: "gitlab.com", Path: "group/project"}, testDigest)
	if err != nil {
		t.Fatalf("FetchAttestations: %v", err)
	}
	if len(statements) != 1 {
		t.Fatalf("got %d statements, want 1", len(statements))
	}
	if statements[0].SourceURL != srv.URL+bundlePath {
		t.Errorf("SourceURL = %q, want %q", statements[0].SourceURL, srv.URL+bundlePath)
	}
	if !strings.Contains(gotListPath, "/projects/group%2Fproject/attestations/"+testDigest) {
		t.Errorf("unexpected list path: %s", gotListPath)
	}
	if gotToken != "glpat-xyz" {
		t.Errorf("PRIVATE-TOKEN = %q", gotToken)
	}
}

func TestFetchAttestationsUnsupportedProvider(t *testing.T) {
	_, err := FetchAttestations(context.Background(), http.DefaultClient, "bitbucket", "https://api.bitbucket.org", "tok", Repo{}, testDigest)
	if err == nil {
		t.Fatal("expected error for unsupported provider")
	}
}

func TestFetchAttestationsInvalidDigest(t *testing.T) {
	_, err := FetchAttestations(context.Background(), http.DefaultClient, ProviderGitHub, "https://api.github.com", "tok", Repo{Path: "a/b"}, "not-a-digest")
	if err == nil {
		t.Fatal("expected error for invalid digest")
	}
}

func TestResolveProvider(t *testing.T) {
	providers := []ProviderConfig{
		{Provider: ProviderGitHub, Host: "github.com", APIBase: "https://api.github.com", Token: "t1"},
		{Provider: ProviderGitLab, Host: "gitlab.com", APIBase: "https://gitlab.com/api/v4", Token: "t2"},
	}
	if _, ok := ResolveProvider(providers, ProviderGitHub, "github.com"); !ok {
		t.Error("expected github/github.com match")
	}
	if _, ok := ResolveProvider(providers, ProviderGitHub, "gitlab.com"); ok {
		t.Error("did not expect a match for github provider with gitlab.com host")
	}
	if cfg, ok := ResolveProvider(providers, ProviderGitLab, ""); !ok || cfg.Token != "t2" {
		t.Errorf("expected gitlab match with empty host, got %v %v", cfg, ok)
	}
	if _, ok := ResolveProvider(providers, "bitbucket", ""); ok {
		t.Error("did not expect a match for an unconfigured provider")
	}
}
