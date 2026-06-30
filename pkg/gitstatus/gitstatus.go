// Package gitstatus posts Fides compliance verdicts as commit statuses on
// GitHub and GitLab, so branch-protection / merge rules can gate merges and
// deploys on Fides compliance. It is an events.Sink driven by the event core.
package gitstatus

import (
	"fmt"
	"net/url"
	"strings"
)

// Provider identifies the SCM platform.
const (
	ProviderGitHub = "github"
	ProviderGitLab = "gitlab"
)

// Repo is a parsed git remote.
type Repo struct {
	Host string // e.g. github.com, gitlab.example.com
	Path string // e.g. owner/repo, group/subgroup/project (no scheme, no ".git")
}

// OwnerRepo returns the GitHub-style "owner/repo" (first two path segments).
func (r Repo) OwnerRepo() (string, error) {
	parts := strings.Split(r.Path, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("repo path %q is not owner/repo", r.Path)
	}
	return parts[0] + "/" + parts[1], nil
}

// ParseRepo extracts host and path from an https or scp-style git remote.
func ParseRepo(raw string) (Repo, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Repo{}, fmt.Errorf("empty repository url")
	}

	var host, path string
	// scp-style: git@host:owner/repo.git
	if !strings.Contains(raw, "://") && strings.Contains(raw, "@") && strings.Contains(raw, ":") {
		raw = strings.TrimPrefix(raw, "ssh://")
		at := strings.LastIndex(raw, "@")
		rest := raw[at+1:]
		colon := strings.Index(rest, ":")
		host = rest[:colon]
		path = rest[colon+1:]
	} else {
		u, err := url.Parse(raw)
		if err != nil {
			return Repo{}, fmt.Errorf("invalid repository url: %w", err)
		}
		host = u.Host
		path = u.Path
	}

	host = strings.TrimSpace(host)
	path = strings.Trim(path, "/")
	path = strings.TrimSuffix(path, ".git")
	if host == "" || path == "" {
		return Repo{}, fmt.Errorf("could not parse host/path from %q", raw)
	}
	return Repo{Host: host, Path: path}, nil
}

// Verdict is the compliance outcome to publish.
type Verdict struct {
	Compliant   bool
	Context     string // status context/name, e.g. "fides/compliance"
	Description string
	TargetURL   string // link to the evidence in Fides
}

// githubState maps a verdict to a GitHub commit-status state.
func githubState(compliant bool) string {
	if compliant {
		return "success"
	}
	return "failure"
}

// gitlabState maps a verdict to a GitLab commit-status state.
func gitlabState(compliant bool) string {
	if compliant {
		return "success"
	}
	return "failed"
}
