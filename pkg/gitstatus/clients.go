package gitstatus

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// PostStatus publishes the verdict as a commit status on the given commit using
// the provider client. apiBase is the API root (e.g. https://api.github.com or
// https://gitlab.com/api/v4); token authenticates the call.
func PostStatus(ctx context.Context, c *http.Client, provider, apiBase, token string, repo Repo, commit string, v Verdict) error {
	switch provider {
	case ProviderGitHub:
		return postGitHub(ctx, c, apiBase, token, repo, commit, v)
	case ProviderGitLab:
		return postGitLab(ctx, c, apiBase, token, repo, commit, v)
	case ProviderBitbucket:
		return postBitbucket(ctx, c, apiBase, token, repo, commit, v)
	case ProviderAzureDevOps:
		return postAzureDevOps(ctx, c, apiBase, token, repo, commit, v)
	default:
		return fmt.Errorf("unsupported git provider %q", provider)
	}
}

func postGitHub(ctx context.Context, c *http.Client, apiBase, token string, repo Repo, commit string, v Verdict) error {
	ownerRepo, err := repo.OwnerRepo()
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(apiBase, "/") + "/repos/" + ownerRepo + "/statuses/" + commit
	body, _ := json.Marshal(map[string]string{
		"state":       githubState(v.Compliant),
		"target_url":  v.TargetURL,
		"description": v.Description,
		"context":     v.Context,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	return do(c, req)
}

func postGitLab(ctx context.Context, c *http.Client, apiBase, token string, repo Repo, commit string, v Verdict) error {
	endpoint := strings.TrimRight(apiBase, "/") + "/projects/" + url.PathEscape(repo.Path) + "/statuses/" + commit
	body, _ := json.Marshal(map[string]string{
		"state":       gitlabState(v.Compliant),
		"name":        v.Context,
		"target_url":  v.TargetURL,
		"description": v.Description,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	req.Header.Set("Content-Type", "application/json")
	return do(c, req)
}

// postBitbucket publishes a build status. apiBase e.g. https://api.bitbucket.org/2.0;
// repo.Path is "workspace/repo"; token is a Bitbucket access token / app password bearer.
func postBitbucket(ctx context.Context, c *http.Client, apiBase, token string, repo Repo, commit string, v Verdict) error {
	ownerRepo, err := repo.OwnerRepo()
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(apiBase, "/") + "/repositories/" + ownerRepo + "/commit/" + commit + "/statuses/build"
	key := v.Context
	if key == "" {
		key = "fides"
	}
	body, _ := json.Marshal(map[string]string{
		"key": key, "state": bitbucketState(v.Compliant),
		"url": v.TargetURL, "description": v.Description, "name": v.Context,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return do(c, req)
}

// postAzureDevOps publishes a commit status. apiBase e.g. https://dev.azure.com/{org};
// repo.Path is "project/repo"; token is a PAT (used via Basic auth).
func postAzureDevOps(ctx context.Context, c *http.Client, apiBase, token string, repo Repo, commit string, v Verdict) error {
	ownerRepo, err := repo.OwnerRepo()
	if err != nil {
		return err
	}
	parts := strings.SplitN(ownerRepo, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("azure-devops repo path must be project/repo, got %q", repo.Path)
	}
	project, repository := parts[0], parts[1]
	endpoint := strings.TrimRight(apiBase, "/") + "/" + url.PathEscape(project) +
		"/_apis/git/repositories/" + url.PathEscape(repository) + "/commits/" + commit + "/statuses?api-version=7.1"
	body, _ := json.Marshal(map[string]any{
		"state":       azureState(v.Compliant),
		"description": v.Description,
		"targetUrl":   v.TargetURL,
		"context":     map[string]string{"name": v.Context, "genre": "fides"},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	// Azure DevOps PAT auth: Basic with an empty username.
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(":"+token)))
	req.Header.Set("Content-Type", "application/json")
	return do(c, req)
}

func do(c *http.Client, req *http.Request) error {
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("commit status returned %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}
