// Package inbound verifies and parses inbound CI/CD webhooks (GitHub, GitLab)
// so Fides can auto-create a trail for a pushed commit.
package inbound

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// Providers.
const (
	GitHub      = "github"
	GitLab      = "gitlab"
	Bitbucket   = "bitbucket"
	AzureDevOps = "azure-devops"
)

// TrailInfo is the provenance extracted from a push event.
type TrailInfo struct {
	Repository string // remote URL
	FullName   string // owner/repo or group/project
	Commit     string // commit SHA
	Branch     string // branch name (ref without refs/heads/)
	Message    string // head commit message
}

// VerifyGitHub checks the X-Hub-Signature-256 header ("sha256=<hex>") against an
// HMAC-SHA256 of the raw body, in constant time.
func VerifyGitHub(secret string, signatureHeader string, body []byte) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(signatureHeader, prefix) {
		return false
	}
	want, err := hex.DecodeString(strings.TrimPrefix(signatureHeader, prefix))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), want)
}

// VerifyGitLab compares the X-Gitlab-Token header against the configured secret
// in constant time (GitLab sends a plain shared token, not an HMAC).
func VerifyGitLab(secret, tokenHeader string) bool {
	if secret == "" || tokenHeader == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(secret), []byte(tokenHeader)) == 1
}

// Verify dispatches to the provider-specific check. Bitbucket (Server/DC) signs
// with X-Hub-Signature (HMAC-SHA256, like GitHub); Azure DevOps service hooks use
// a shared token (like GitLab).
func Verify(provider, secret, sigOrToken string, body []byte) bool {
	switch provider {
	case GitHub:
		return VerifyGitHub(secret, sigOrToken, body)
	case Bitbucket:
		return VerifyGitHub(secret, sigOrToken, body)
	case GitLab:
		return VerifyGitLab(secret, sigOrToken)
	case AzureDevOps:
		return VerifyGitLab(secret, sigOrToken)
	default:
		return false
	}
}

type githubPush struct {
	Ref        string `json:"ref"`
	After      string `json:"after"`
	Repository struct {
		FullName string `json:"full_name"`
		CloneURL string `json:"clone_url"`
	} `json:"repository"`
	HeadCommit struct {
		ID      string `json:"id"`
		Message string `json:"message"`
	} `json:"head_commit"`
}

type gitlabPush struct {
	ObjectKind  string `json:"object_kind"`
	Ref         string `json:"ref"`
	CheckoutSHA string `json:"checkout_sha"`
	Project     struct {
		PathWithNamespace string `json:"path_with_namespace"`
		GitHTTPURL        string `json:"git_http_url"`
	} `json:"project"`
	Commits []struct {
		ID      string `json:"id"`
		Message string `json:"message"`
	} `json:"commits"`
}

type bitbucketPush struct {
	Push struct {
		Changes []struct {
			New struct {
				Name   string `json:"name"`
				Target struct {
					Hash    string `json:"hash"`
					Message string `json:"message"`
				} `json:"target"`
			} `json:"new"`
		} `json:"changes"`
	} `json:"push"`
	Repository struct {
		FullName string `json:"full_name"`
		Links    struct {
			HTML struct {
				Href string `json:"href"`
			} `json:"html"`
		} `json:"links"`
	} `json:"repository"`
}

type azurePush struct {
	Resource struct {
		RefUpdates []struct {
			Name        string `json:"name"`
			NewObjectID string `json:"newObjectId"`
		} `json:"refUpdates"`
		Commits []struct {
			CommitID string `json:"commitId"`
			Comment  string `json:"comment"`
		} `json:"commits"`
		Repository struct {
			Name      string `json:"name"`
			RemoteURL string `json:"remoteUrl"`
			Project   struct {
				Name string `json:"name"`
			} `json:"project"`
		} `json:"repository"`
	} `json:"resource"`
}

// ParsePush extracts trail provenance from a push event. It returns false if the
// event is not a parseable push with a commit SHA.
func ParsePush(provider string, body []byte) (TrailInfo, bool) {
	switch provider {
	case GitHub:
		var p githubPush
		if err := json.Unmarshal(body, &p); err != nil {
			return TrailInfo{}, false
		}
		commit := p.After
		if commit == "" {
			commit = p.HeadCommit.ID
		}
		if commit == "" {
			return TrailInfo{}, false
		}
		return TrailInfo{
			Repository: p.Repository.CloneURL,
			FullName:   p.Repository.FullName,
			Commit:     commit,
			Branch:     branchFromRef(p.Ref),
			Message:    p.HeadCommit.Message,
		}, true
	case GitLab:
		var p gitlabPush
		if err := json.Unmarshal(body, &p); err != nil || p.ObjectKind != "push" {
			return TrailInfo{}, false
		}
		commit := p.CheckoutSHA
		msg := ""
		if len(p.Commits) > 0 {
			if commit == "" {
				commit = p.Commits[len(p.Commits)-1].ID
			}
			msg = p.Commits[len(p.Commits)-1].Message
		}
		if commit == "" {
			return TrailInfo{}, false
		}
		return TrailInfo{
			Repository: p.Project.GitHTTPURL,
			FullName:   p.Project.PathWithNamespace,
			Commit:     commit,
			Branch:     branchFromRef(p.Ref),
			Message:    msg,
		}, true
	case Bitbucket:
		var p bitbucketPush
		if err := json.Unmarshal(body, &p); err != nil || len(p.Push.Changes) == 0 {
			return TrailInfo{}, false
		}
		ch := p.Push.Changes[0].New
		if ch.Target.Hash == "" {
			return TrailInfo{}, false
		}
		return TrailInfo{
			Repository: p.Repository.Links.HTML.Href,
			FullName:   p.Repository.FullName,
			Commit:     ch.Target.Hash,
			Branch:     ch.Name,
			Message:    ch.Target.Message,
		}, true
	case AzureDevOps:
		var p azurePush
		if err := json.Unmarshal(body, &p); err != nil || len(p.Resource.RefUpdates) == 0 {
			return TrailInfo{}, false
		}
		commit := p.Resource.RefUpdates[0].NewObjectID
		msg := ""
		if len(p.Resource.Commits) > 0 {
			if commit == "" {
				commit = p.Resource.Commits[0].CommitID
			}
			msg = p.Resource.Commits[0].Comment
		}
		if commit == "" {
			return TrailInfo{}, false
		}
		return TrailInfo{
			Repository: p.Resource.Repository.RemoteURL,
			FullName:   p.Resource.Repository.Project.Name + "/" + p.Resource.Repository.Name,
			Commit:     commit,
			Branch:     branchFromRef(p.Resource.RefUpdates[0].Name),
			Message:    msg,
		}, true
	default:
		return TrailInfo{}, false
	}
}

func branchFromRef(ref string) string {
	return strings.TrimPrefix(ref, "refs/heads/")
}
