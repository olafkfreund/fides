package gitstatus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// BranchProtection is the subset of a branch's protection rules Fides evidences.
type BranchProtection struct {
	Branch          string `json:"branch"`
	Protected       bool   `json:"protected"`
	RequiredReviews int    `json:"required_reviews"`
}

// GetBranchProtection queries the git provider for a branch's protection rules,
// so Fides can attest them instead of taking them on trust.
func GetBranchProtection(ctx context.Context, c *http.Client, provider, apiBase, token string, repo Repo, branch string) (BranchProtection, error) {
	switch provider {
	case "github":
		return githubBranchProtection(ctx, c, apiBase, token, repo, branch)
	case "gitlab":
		return gitlabBranchProtection(ctx, c, apiBase, token, repo, branch)
	default:
		return BranchProtection{}, fmt.Errorf("branch-protection verification not supported for provider %q", provider)
	}
}

func githubBranchProtection(ctx context.Context, c *http.Client, apiBase, token string, repo Repo, branch string) (BranchProtection, error) {
	ownerRepo, err := repo.OwnerRepo()
	if err != nil {
		return BranchProtection{}, err
	}
	endpoint := strings.TrimRight(apiBase, "/") + "/repos/" + ownerRepo + "/branches/" + url.PathEscape(branch) + "/protection"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req)
	if err != nil {
		return BranchProtection{}, err
	}
	defer resp.Body.Close()
	// 404 = the branch has no protection configured (unprotected), not an error.
	if resp.StatusCode == http.StatusNotFound {
		return BranchProtection{Branch: branch, Protected: false}, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return BranchProtection{}, fmt.Errorf("github branch protection: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var gp struct {
		RequiredPullRequestReviews struct {
			RequiredApprovingReviewCount int `json:"required_approving_review_count"`
		} `json:"required_pull_request_reviews"`
	}
	_ = json.Unmarshal(body, &gp)
	return BranchProtection{
		Branch:          branch,
		Protected:       true,
		RequiredReviews: gp.RequiredPullRequestReviews.RequiredApprovingReviewCount,
	}, nil
}

func gitlabBranchProtection(ctx context.Context, c *http.Client, apiBase, token string, repo Repo, branch string) (BranchProtection, error) {
	endpoint := strings.TrimRight(apiBase, "/") + "/projects/" + url.PathEscape(repo.Path) + "/protected_branches/" + url.PathEscape(branch)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("PRIVATE-TOKEN", token)
	resp, err := c.Do(req)
	if err != nil {
		return BranchProtection{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return BranchProtection{Branch: branch, Protected: false}, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return BranchProtection{}, fmt.Errorf("gitlab protected branch: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	// GitLab records approvals separately; the presence of a protected-branch
	// entry means the branch is protected. RequiredReviews is reported by the
	// approval-rules API (not fetched here) — left 0.
	return BranchProtection{Branch: branch, Protected: true}, nil
}
