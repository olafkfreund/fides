package inbound

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func githubSig(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyGitHub(t *testing.T) {
	body := []byte(`{"after":"abc"}`)
	if !VerifyGitHub("s3cr3t", githubSig("s3cr3t", body), body) {
		t.Fatalf("valid signature should verify")
	}
	if VerifyGitHub("wrong", githubSig("s3cr3t", body), body) {
		t.Fatalf("wrong secret must fail")
	}
	if VerifyGitHub("s3cr3t", "sha256=deadbeef", body) {
		t.Fatalf("bad signature must fail")
	}
	if VerifyGitHub("s3cr3t", "notprefixed", body) {
		t.Fatalf("missing prefix must fail")
	}
}

func TestVerifyGitLab(t *testing.T) {
	if !VerifyGitLab("tok", "tok") {
		t.Fatalf("matching token should verify")
	}
	if VerifyGitLab("tok", "nope") || VerifyGitLab("", "") {
		t.Fatalf("mismatched/empty token must fail")
	}
}

func TestParsePushGitHub(t *testing.T) {
	body := []byte(`{
		"ref":"refs/heads/main",
		"after":"1234567890abcdef",
		"repository":{"full_name":"acme/widgets","clone_url":"https://github.com/acme/widgets.git"},
		"head_commit":{"id":"1234567890abcdef","message":"fix bug"}
	}`)
	ti, ok := ParsePush(GitHub, body)
	if !ok {
		t.Fatalf("expected a parseable push")
	}
	if ti.Commit != "1234567890abcdef" || ti.Branch != "main" || ti.FullName != "acme/widgets" || ti.Message != "fix bug" {
		t.Fatalf("parsed wrong: %+v", ti)
	}
}

func TestParsePushGitLab(t *testing.T) {
	body := []byte(`{
		"object_kind":"push",
		"ref":"refs/heads/dev",
		"checkout_sha":"deadbeef",
		"project":{"path_with_namespace":"grp/proj","git_http_url":"https://gitlab.com/grp/proj.git"},
		"commits":[{"id":"deadbeef","message":"feat"}]
	}`)
	ti, ok := ParsePush(GitLab, body)
	if !ok || ti.Commit != "deadbeef" || ti.Branch != "dev" || ti.FullName != "grp/proj" {
		t.Fatalf("parsed wrong: %+v ok=%v", ti, ok)
	}

	// Non-push GitLab event -> not parseable.
	if _, ok := ParsePush(GitLab, []byte(`{"object_kind":"issue"}`)); ok {
		t.Fatalf("non-push event must not parse")
	}
}

func TestParsePushNoCommit(t *testing.T) {
	if _, ok := ParsePush(GitHub, []byte(`{"ref":"refs/heads/main"}`)); ok {
		t.Fatalf("a push with no commit sha must not parse")
	}
}
