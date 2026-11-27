package gitstatus

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"
)

type attestationTransport func(*http.Request) (*http.Response, error)

func (f attestationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func attestationResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}
}

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

	const api = "https://api.example.test"
	listPath := "/repos/acme/widgets/attestations/sha256:" + testDigest
	client := &http.Client{Transport: attestationTransport(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok123" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
			t.Errorf("Accept = %q", got)
		}
		switch r.URL.Path {
		case listPath:
			return attestationResponse(fmt.Sprintf(`{"attestations":[{"repository_id":1,"bundle_url":%q}]}`, api+listPath+"/bundle")), nil
		case listPath + "/bundle":
			return attestationResponse(bundleJSON), nil
		default:
			return nil, fmt.Errorf("unexpected path: %s", r.URL.Path)
		}
	})}
	statements, err := FetchAttestations(context.Background(), client, ProviderGitHub, api, "tok123", Repo{Host: "github.com", Path: "acme/widgets"}, testDigest)
	if err != nil {
		t.Fatalf("FetchAttestations: %v", err)
	}
	if len(statements) != 1 {
		t.Fatalf("got %d statements, want 1", len(statements))
	}
	if statements[0].PredicateType != "https://slsa.dev/provenance/v1" {
		t.Errorf("PredicateType = %q", statements[0].PredicateType)
	}
}

func TestFetchGitLabAttestations(t *testing.T) {
	bundleJSON := sigstoreBundleJSON(t, map[string]any{
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject":       []map[string]any{{"name": "app", "digest": map[string]string{"sha256": testDigest}}},
	})

	const api = "http://10.0.0.5/api/v4"
	client := &http.Client{Transport: attestationTransport(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("PRIVATE-TOKEN"); got != "glpat-xyz" {
			t.Errorf("PRIVATE-TOKEN = %q", got)
		}
		switch r.URL.EscapedPath() {
		case "/api/v4/projects/group%2Fproject/attestations/" + testDigest:
			return attestationResponse(fmt.Sprintf(`[{"iid":1,"download_url":%q}]`, api+"/projects/group%2Fproject/attestations/1/download")), nil
		case "/api/v4/projects/group%2Fproject/attestations/1/download":
			return attestationResponse(bundleJSON), nil
		default:
			return nil, fmt.Errorf("unexpected path: %s", r.URL.EscapedPath())
		}
	})}

	statements, err := FetchAttestations(context.Background(), client, ProviderGitLab, api, "glpat-xyz", Repo{Host: "gitlab.com", Path: "group/project"}, testDigest)
	if err != nil {
		t.Fatalf("FetchAttestations: %v", err)
	}
	if len(statements) != 1 {
		t.Fatalf("got %d statements, want 1", len(statements))
	}
}

func TestAttestationRedirects(t *testing.T) {
	const api = "https://api.example.test"
	for _, tt := range []struct {
		destination string
		wantCalls   int
	}{
		{"https://API.example.test:443/next", 2},
		{"https://storage.example.test/next", 1},
		{"https://api.example.test:8443/next", 1},
		{"http://api.example.test/next", 1},
	} {
		t.Run(tt.destination, func(t *testing.T) {
			calls, redirects := 0, 0
			client := &http.Client{
				CheckRedirect: func(*http.Request, []*http.Request) error {
					redirects++
					return nil
				},
				Transport: attestationTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					if r.Header.Get("Authorization") != "Bearer test-token" {
						t.Error("missing provider token")
					}
					if r.URL.Path == "/next" {
						return attestationResponse(`{"attestations":[]}`), nil
					}
					return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {tt.destination}}, Body: http.NoBody}, nil
				}),
			}
			_, err := FetchAttestations(context.Background(), client, ProviderGitHub, api, "test-token", Repo{Path: "group/project"}, testDigest)
			if calls != tt.wantCalls || redirects != tt.wantCalls-1 || (err != nil) != (tt.wantCalls == 1) {
				t.Fatalf("got %d deliveries, %d redirect callbacks, error %v", calls, redirects, err)
			}
		})
	}
}

func TestSignedAttestationDownloads(t *testing.T) {
	origin, err := url.Parse("https://api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	provider := &http.Client{Jar: jar, Timeout: time.Second}
	headers := map[string]string{"Authorization": "Bearer test-token", "Private-Token": "test-token"}
	ctx := context.Background()
	for _, endpoint := range []string{"http://192.0.2.1/bundle", "https://10.0.0.5/bundle"} {
		if _, _, err := bundleRequest(ctx, provider, origin, endpoint, headers); err == nil {
			t.Fatalf("accepted disallowed download destination %s", endpoint)
		}
	}

	const signedURL = "https://192.0.2.1/bundle?signature=fixture"
	client, req, err := bundleRequest(ctx, provider, origin, signedURL, headers)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if client == provider || client.Jar != nil || client.Timeout != provider.Timeout || !ok || transport.Proxy != nil || transport.DialContext == nil {
		t.Fatal("expected a separate guarded download client without cookies or proxy")
	}
	if got := signedDownloadSource(req.URL); got != "https://192.0.2.1/bundle" {
		t.Errorf("signed download metadata = %q, want URL without the signature", got)
	}
	client.Transport = attestationTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != signedURL || len(r.Header) != 0 {
			t.Errorf("unexpected signed request URL or headers: %s %v", r.URL, r.Header)
		}
		return attestationResponse("bundle"), nil
	})
	if body, err := getBody(client, req); err != nil || string(body) != "bundle" {
		t.Fatalf("signed download got %q, %v", body, err)
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
