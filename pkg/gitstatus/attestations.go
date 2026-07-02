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
	switch provider {
	case ProviderGitHub:
		return fetchGitHubAttestations(ctx, c, apiBase, token, repo, sha)
	case ProviderGitLab:
		return fetchGitLabAttestations(ctx, c, apiBase, token, repo, sha)
	default:
		return nil, fmt.Errorf("attestation ingest is not supported for git provider %q (supported: github, gitlab)", provider)
	}
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

func fetchGitHubAttestations(ctx context.Context, c *http.Client, apiBase, token string, repo Repo, sha string) ([]Statement, error) {
	ownerRepo, err := repo.OwnerRepo()
	if err != nil {
		return nil, err
	}
	digest := "sha256:" + sha
	endpoint := strings.TrimRight(apiBase, "/") + "/repos/" + ownerRepo + "/attestations/" + url.PathEscape(digest)
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
		stmt, err := fetchBundle(ctx, c, a.BundleURL, headers)
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

func fetchGitLabAttestations(ctx context.Context, c *http.Client, apiBase, token string, repo Repo, sha string) ([]Statement, error) {
	endpoint := strings.TrimRight(apiBase, "/") + "/projects/" + url.PathEscape(repo.Path) + "/attestations/" + sha
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
		stmt, err := fetchBundle(ctx, c, a.DownloadURL, headers)
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

func fetchBundle(ctx context.Context, c *http.Client, endpoint string, headers map[string]string) (Statement, error) {
	body, err := getBody(ctx, c, endpoint, headers)
	if err != nil {
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
	return Statement{PredicateType: meta.PredicateType, Statement: statement, SourceURL: endpoint}, nil
}

func getJSON(ctx context.Context, c *http.Client, endpoint string, headers map[string]string, out any) error {
	body, err := getBody(ctx, c, endpoint, headers)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func getBody(ctx context.Context, c *http.Client, endpoint string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
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
