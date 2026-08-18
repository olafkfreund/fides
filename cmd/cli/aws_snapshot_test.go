package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	realDigest = "3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f"
	otherHex   = "c127b69288d60290be9a2da7fc220d8dd161921aa4b18dff75c98a1cc14a229a"
)

func artFor(arts []map[string]string, service string) (map[string]string, bool) {
	for _, a := range arts {
		if a["service_name"] == service {
			return a, true
		}
	}
	return nil, false
}

// AWS returns imageDigest ONLY for images pulled from a private ECR repository;
// for Docker Hub, public ECR, GHCR and everything else the field is omitted
// (aws/containers-roadmap#1640). The old code did
// strings.TrimPrefix(c.ImageDigest, "sha256:") unconditionally, so those
// containers were reported running with sha256 "" -- a value that can never
// match a registered artifact or an allowlist entry, producing a shadow change
// no correct action could ever clear. Same defect class as #406/#430.
func TestECSSkipsContainersWithoutADigest(t *testing.T) {
	out := fmt.Sprintf(`{"tasks":[{"taskArn":"arn:aws:ecs:eu-west-2:1:task/abc","containers":[
	  {"name":"from-ecr","image":"1.dkr.ecr.eu-west-2.amazonaws.com/api:v1","imageDigest":"sha256:%s"},
	  {"name":"from-dockerhub","image":"postgres:15-alpine"},
	  {"name":"empty-digest","image":"nginx:latest","imageDigest":""}
	]}]}`, realDigest)

	arts := ecsSnapshotArtifacts(out)

	if len(arts) != 1 {
		t.Fatalf("expected only the ECR container to be reported, got %d: %v", len(arts), arts)
	}
	got, _ := artFor(arts, "from-ecr")
	if got["sha256"] != realDigest {
		t.Errorf("sha256 = %q, want the bare hex digest", got["sha256"])
	}
	for _, skipped := range []string{"from-dockerhub", "empty-digest"} {
		if a, found := artFor(arts, skipped); found {
			t.Errorf("%s must be skipped, not reported as %q", skipped, a["sha256"])
		}
	}
}

// CodeSha256 is the hash of the function's DEPLOYMENT PACKAGE. For
// PackageType=Image that package is Lambda's own optimized copy of the
// container, which AWS documents as "not the same key that's used to protect
// your container image in Amazon ECR". It is 64 hex chars, so it looks exactly
// like an image digest and passes every length/format check -- and can never
// equal the digest `fides artifact report` registered at build time.
//
// The running digest is Code.ResolvedImageUri, which Lambda pins at deploy.
func TestLambdaContainerFunctionUsesResolvedImageUriNotCodeSha256(t *testing.T) {
	codeSha := base64.StdEncoding.EncodeToString(mustHex(t, otherHex))
	list := fmt.Sprintf(`{"Functions":[
	  {"FunctionName":"container-fn","PackageType":"Image","CodeSha256":%q}
	]}`, codeSha)

	var asked []string
	arts := lambdaSnapshotArtifacts(list, func(name string) (string, error) {
		asked = append(asked, name)
		return fmt.Sprintf(`{"Code":{"ImageUri":"1.dkr.ecr.eu-west-2.amazonaws.com/fn:latest",
		  "ResolvedImageUri":"1.dkr.ecr.eu-west-2.amazonaws.com/fn@sha256:%s"}}`, realDigest), nil
	})

	if len(arts) != 1 {
		t.Fatalf("expected 1 artifact, got %d: %v", len(arts), arts)
	}
	if arts[0]["sha256"] != realDigest {
		t.Errorf("sha256 = %q, want the ECR digest %q", arts[0]["sha256"], realDigest)
	}
	if arts[0]["sha256"] == otherHex {
		t.Error("reported CodeSha256 as the image digest — it is Lambda's optimized " +
			"package hash and can never match a registered artifact")
	}
	if len(asked) != 1 || asked[0] != "container-fn" {
		t.Errorf("get-function should be called once for the image function, got %v", asked)
	}
}

// Zip functions are the case CodeSha256 is actually correct for, so the extra
// get-function call must NOT happen for them.
func TestLambdaZipFunctionUsesCodeSha256AndSkipsExtraCall(t *testing.T) {
	list := fmt.Sprintf(`{"Functions":[
	  {"FunctionName":"zip-fn","PackageType":"Zip","CodeSha256":%q}
	]}`, base64.StdEncoding.EncodeToString(mustHex(t, realDigest)))

	called := false
	arts := lambdaSnapshotArtifacts(list, func(string) (string, error) {
		called = true
		return "", errors.New("get-function must not be called for a zip function")
	})

	if called {
		t.Error("called get-function for a Zip function; CodeSha256 is already correct there")
	}
	if len(arts) != 1 || arts[0]["sha256"] != realDigest {
		t.Fatalf("want the decoded CodeSha256 hex, got %v", arts)
	}
}

// A tag-pinned ImageUri answers a different question than "what is running".
// Falling back to it would be inventing an observation.
func TestLambdaSkipsWhenNoDigestResolvable(t *testing.T) {
	list := `{"Functions":[
	  {"FunctionName":"unresolvable","PackageType":"Image","CodeSha256":"irrelevant"},
	  {"FunctionName":"errored","PackageType":"Image","CodeSha256":"irrelevant"}
	]}`

	arts := lambdaSnapshotArtifacts(list, func(name string) (string, error) {
		if name == "errored" {
			return "", errors.New("AccessDenied")
		}
		// Resolved to a TAG, not a digest.
		return `{"Code":{"ImageUri":"1.dkr.ecr.eu-west-2.amazonaws.com/fn:latest",
		  "ResolvedImageUri":"1.dkr.ecr.eu-west-2.amazonaws.com/fn:latest"}}`, nil
	})

	if len(arts) != 0 {
		t.Fatalf("nothing resolvable should be reported; got %v", arts)
	}
}

// One malformed function must not discard the rest of the estate.
func TestLambdaOneBadFunctionDoesNotDropTheOthers(t *testing.T) {
	list := fmt.Sprintf(`{"Functions":[
	  {"FunctionName":"bad","PackageType":"Image","CodeSha256":"x"},
	  {"FunctionName":"good","PackageType":"Zip","CodeSha256":%q}
	]}`, base64.StdEncoding.EncodeToString(mustHex(t, realDigest)))

	arts := lambdaSnapshotArtifacts(list, func(string) (string, error) {
		return "", errors.New("boom")
	})
	if len(arts) != 1 {
		t.Fatalf("expected the good function to survive, got %v", arts)
	}
	if arts[0]["service_name"] != "good" {
		t.Errorf("wrong survivor: %v", arts)
	}
}

// Unparseable input must yield nothing rather than panicking or fabricating.
func TestAWSSnapshotHandlesGarbageInput(t *testing.T) {
	if a := ecsSnapshotArtifacts("not json"); len(a) != 0 {
		t.Errorf("ecs: %v", a)
	}
	if a := lambdaSnapshotArtifacts("not json", func(string) (string, error) { return "", nil }); len(a) != 0 {
		t.Errorf("lambda: %v", a)
	}
}

func TestResolvedImageDigestAndCodeSha256Decoding(t *testing.T) {
	if got := resolvedImageDigest(fmt.Sprintf(`{"Code":{"ResolvedImageUri":"r/f@sha256:%s"}}`, realDigest)); got != realDigest {
		t.Errorf("resolvedImageDigest = %q", got)
	}
	// Already-hex CodeSha256 passes through; base64 is decoded.
	if got := decodeCodeSha256(realDigest); got != realDigest {
		t.Errorf("hex passthrough = %q", got)
	}
	b64 := base64.StdEncoding.EncodeToString(mustHex(t, realDigest))
	if got := decodeCodeSha256(b64); got != realDigest {
		t.Errorf("base64 decode = %q, want %q", got, realDigest)
	}
	if strings.Contains(b64, realDigest) {
		t.Fatal("fixture is not actually base64-encoded; the decode assertion above is vacuous")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	return b
}
