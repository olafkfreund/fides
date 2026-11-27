package gitstatus

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"fides/internal/outbound"
)

// Statement is one platform-native attestation fetched from a git provider's
// attestation store, with its Sigstore bundle's DSSE envelope decoded down to
// the raw in-toto statement (predicateType/subject/predicate) so pkg/evidence
// can normalize it into a Result.
type Statement struct {
	PredicateType string // from the decoded in-toto statement, for display/filtering
	Statement     []byte // raw in-toto statement JSON
	SourceURL     string // bundle/download URL it was fetched from, for traceability
}

// FetchAttestations fetches platform-native attestations/provenance for the
// given artifact subject digest (sha256, hex, no "sha256:" prefix) from the
// configured git provider (GitHub Artifact Attestations, GitLab Attestations),
// decoding each result's Sigstore-bundled DSSE envelope.
func FetchAttestations(ctx context.Context, c *http.Client, provider, apiBase, token string, repo Repo, subjectSHA256 string) ([]Statement, error) {
	sha := strings.ToLower(strings.TrimSpace(subjectSHA256))
	if len(sha) != 64 {
		return nil, fmt.Errorf("artifact sha256 must be a 64-character hex digest, got %d characters", len(sha))
	}
	if provider != ProviderGitHub && provider != ProviderGitLab {
		return nil, fmt.Errorf("attestation ingest is not supported for git provider %q (supported: github, gitlab)", provider)
	}
	origin, err := parseAttestationURL(apiBase)
	if err != nil {
		return nil, fmt.Errorf("invalid git provider API URL: %w", err)
	}
	c = attestationClient(c, origin)
	if provider == ProviderGitHub {
		return fetchGitHubAttestations(ctx, c, origin, token, repo, sha)
	}
	return fetchGitLabAttestations(ctx, c, origin, token, repo, sha)
}

func parseAttestationURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return nil, fmt.Errorf("expected an absolute HTTP(S) URL without user information")
	}
	return u, nil
}

func attestationClient(c *http.Client, origin *url.URL) *http.Client {
	client := *c
	checkOrigin := func(req *http.Request) error {
		if req.URL.User != nil || !outbound.SameOrigin(origin, req.URL) {
			return fmt.Errorf("attestation redirect must stay on the initial origin")
		}
		return nil
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := checkOrigin(req); err != nil {
			return err
		}
		// net/http may strip Authorization when only hostname case changes.
		if auth := via[0].Header.Get("Authorization"); auth != "" && req.Header.Get("Authorization") == "" {
			req.Header.Set("Authorization", auth)
		}
		if c.CheckRedirect != nil {
			if err := c.CheckRedirect(req, via); err != nil {
				return err
			}
			return checkOrigin(req)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	return &client
}

// ResolveProvider picks the configured provider matching wantProvider (and,
// when host is non-empty, also matching the host) from an already-loaded set
// of tenant provider configs.
func ResolveProvider(providers []ProviderConfig, wantProvider, host string) (ProviderConfig, bool) {
	for _, p := range providers {
		if p.Provider != wantProvider {
			continue
		}
		if host != "" && p.Host != host {
			continue
		}
		return p, true
	}
	return ProviderConfig{}, false
}

// githubAttestationsResp is the GitHub REST API "List attestations" response:
// GET /repos/{owner}/{repo}/attestations/{subject_digest}.
type githubAttestationsResp struct {
	Attestations []struct {
		BundleURL string `json:"bundle_url"`
	} `json:"attestations"`
}

func fetchGitHubAttestations(ctx context.Context, c *http.Client, origin *url.URL, token string, repo Repo, sha string) ([]Statement, error) {
	ownerRepo, err := repo.OwnerRepo()
	if err != nil {
		return nil, err
	}
	digest := "sha256:" + sha
	endpoint := strings.TrimRight(origin.String(), "/") + "/repos/" + ownerRepo + "/attestations/" + url.PathEscape(digest)
	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"Accept":        "application/vnd.github+json",
	}
	var list githubAttestationsResp
	if err := getJSON(ctx, c, endpoint, headers, &list); err != nil {
		return nil, fmt.Errorf("list github attestations: %w", err)
	}
	statements := make([]Statement, 0, len(list.Attestations))
	for _, a := range list.Attestations {
		if a.BundleURL == "" {
			continue
		}
		stmt, err := fetchBundle(ctx, c, origin, a.BundleURL, headers)
		if err != nil {
			return nil, fmt.Errorf("fetch github attestation bundle: %w", err)
		}
		statements = append(statements, stmt)
	}
	return statements, nil
}

// gitlabAttestation is one entry of the GitLab Attestations API "List
// attestations" response: GET /projects/{id}/attestations/{subject_digest}.
type gitlabAttestation struct {
	IID           int    `json:"iid"`
	PredicateType string `json:"predicate_type"`
	DownloadURL   string `json:"download_url"`
}

func fetchGitLabAttestations(ctx context.Context, c *http.Client, origin *url.URL, token string, repo Repo, sha string) ([]Statement, error) {
	endpoint := strings.TrimRight(origin.String(), "/") + "/projects/" + url.PathEscape(repo.Path) + "/attestations/" + sha
	headers := map[string]string{"PRIVATE-TOKEN": token}
	var list []gitlabAttestation
	if err := getJSON(ctx, c, endpoint, headers, &list); err != nil {
		return nil, fmt.Errorf("list gitlab attestations: %w", err)
	}
	statements := make([]Statement, 0, len(list))
	for _, a := range list {
		if a.DownloadURL == "" {
			continue
		}
		stmt, err := fetchBundle(ctx, c, origin, a.DownloadURL, headers)
		if err != nil {
			return nil, fmt.Errorf("fetch gitlab attestation bundle: %w", err)
		}
		statements = append(statements, stmt)
	}
	return statements, nil
}

// sigstoreBundle is the minimal shape of a Sigstore bundle (the format both
// GitHub and GitLab return for a single attestation) needed to recover the
// DSSE-enveloped in-toto statement.
type sigstoreBundle struct {
	DSSEEnvelope struct {
		Payload     string `json:"payload"` // base64-encoded in-toto statement JSON
		PayloadType string `json:"payloadType"`
	} `json:"dsseEnvelope"`
}

func bundleRequest(ctx context.Context, provider *http.Client, origin *url.URL, endpoint string, headers map[string]string) (*http.Client, *http.Request, error) {
	u, err := parseAttestationURL(endpoint)
	if err != nil {
		return nil, nil, err
	}
	c := provider
	if !outbound.SameOrigin(origin, u) {
		if err := outbound.ValidateHTTPS(endpoint); err != nil {
			return nil, nil, fmt.Errorf("invalid signed download destination: %w", err)
		}
		c = attestationClient(outbound.NewHTTPSClient(provider.Timeout), u)
		headers = nil
	}
	req, err := attestationRequest(ctx, endpoint, headers)
	return c, req, err
}

func fetchBundle(ctx context.Context, provider *http.Client, origin *url.URL, endpoint string, headers map[string]string) (Statement, error) {
	c, req, err := bundleRequest(ctx, provider, origin, endpoint, headers)
	if err != nil {
		return Statement{}, err
	}
	source := endpoint
	signedDownload := c != provider
	if signedDownload {
		defer c.CloseIdleConnections()
		source = signedDownloadSource(req.URL)
	}
	body, err := getBody(c, req)
	if err != nil {
		if signedDownload {
			return Statement{}, fmt.Errorf("signed bundle download from %s failed", req.URL.Hostname())
		}
		return Statement{}, err
	}
	var bundle sigstoreBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return Statement{}, fmt.Errorf("decode sigstore bundle: %w", err)
	}
	if bundle.DSSEEnvelope.Payload == "" {
		return Statement{}, fmt.Errorf("sigstore bundle has no dsseEnvelope payload")
	}
	statement, err := base64.StdEncoding.DecodeString(bundle.DSSEEnvelope.Payload)
	if err != nil {
		return Statement{}, fmt.Errorf("decode dsse payload: %w", err)
	}
	var meta struct {
		PredicateType string `json:"predicateType"`
	}
	_ = json.Unmarshal(statement, &meta) // best-effort; NormalizeProvenance validates this properly
	return Statement{PredicateType: meta.PredicateType, Statement: statement, SourceURL: source}, nil
}

func signedDownloadSource(endpoint *url.URL) string {
	source := *endpoint
	source.RawQuery, source.Fragment, source.RawFragment = "", "", ""
	source.ForceQuery = false
	return source.String()
}

func getJSON(ctx context.Context, c *http.Client, endpoint string, headers map[string]string, out any) error {
	req, err := attestationRequest(ctx, endpoint, headers)
	if err != nil {
		return err
	}
	body, err := getBody(c, req)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func attestationRequest(ctx context.Context, endpoint string, headers map[string]string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func getBody(c *http.Client, req *http.Request) ([]byte, error) {
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}
