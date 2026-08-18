package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Runtime digest collection for the AWS snapshot paths.
//
// Both functions here follow the rule the Kubernetes path already follows
// (#406, #430): a snapshot artifact is an OBSERVATION of what is running, and
// an observation Fides cannot make is reported as absent, never as a value that
// merely fits the field. A 64-char string that is not the running image's
// digest can never equal a CI-registered artifact or an allowlist entry, so it
// becomes a shadow change that no correct action can clear -- an environment
// pinned at non-compliant for a reason its operator cannot fix.

// ecsSnapshotArtifacts parses `aws ecs describe-tasks` output into snapshot
// artifacts.
//
// imageDigest is only populated for images pulled from a private Amazon ECR
// repository; for Docker Hub, public ECR, GHCR or any other registry AWS omits
// the field entirely (aws/containers-roadmap#1640). Skipping those containers
// with a warning is the honest answer -- reporting "" as the running digest
// would manufacture the unclearable shadow described above.
func ecsSnapshotArtifacts(describeOutput string) []map[string]string {
	var dt struct {
		Tasks []struct {
			TaskArn    string `json:"taskArn"`
			Containers []struct {
				Name        string `json:"name"`
				Image       string `json:"image"`
				ImageDigest string `json:"imageDigest"`
			} `json:"containers"`
		} `json:"tasks"`
	}
	if err := json.Unmarshal([]byte(describeOutput), &dt); err != nil {
		return nil
	}

	var arts []map[string]string
	for _, task := range dt.Tasks {
		for _, c := range task.Containers {
			digest := strings.TrimPrefix(strings.TrimSpace(c.ImageDigest), "sha256:")
			if !isSHA256Hex(digest) {
				fmt.Fprintf(os.Stderr,
					"warning: skipping ECS container %q: no image digest reported (image %q). "+
						"AWS returns imageDigest only for private ECR images.\n",
					c.Name, c.Image)
				continue
			}
			arts = append(arts, map[string]string{"sha256": digest, "service_name": c.Name})
		}
	}
	return arts
}

// lambdaSnapshotArtifacts parses `aws lambda list-functions` output into
// snapshot artifacts, resolving container-image functions through the
// getFunction callback (`aws lambda get-function --function-name <name>`).
//
// The distinction the callback exists for: CodeSha256 is "the SHA256 hash of
// the function's deployment package", and for PackageType=Image the deployment
// package is Lambda's own OPTIMIZED copy of the container -- AWS says outright
// that it is "not the same key that's used to protect your container image in
// Amazon ECR". So for a container function CodeSha256 is a 64-char hex string
// that can never equal the digest `fides artifact report` registered at build
// time. It looks exactly like a digest, which is what makes it dangerous.
//
// The real digest is Code.ResolvedImageUri ("<repo>@sha256:<hex>"), which
// Lambda pins at deploy time. It is only on get-function; list-functions does
// not return it, hence one extra call per image function and none for zip ones.
//
// For PackageType=Zip, CodeSha256 IS the artifact digest and is used as-is,
// base64-decoded (AWS returns it base64, Fides stores hex).
func lambdaSnapshotArtifacts(listOutput string, getFunction func(name string) (string, error)) []map[string]string {
	var fl struct {
		Functions []struct {
			FunctionName string `json:"FunctionName"`
			CodeSha256   string `json:"CodeSha256"`
			PackageType  string `json:"PackageType"`
		} `json:"Functions"`
	}
	if err := json.Unmarshal([]byte(listOutput), &fl); err != nil {
		return nil
	}

	var arts []map[string]string
	for _, f := range fl.Functions {
		var digest string
		if f.PackageType == "Image" {
			out, err := getFunction(f.FunctionName)
			if err != nil {
				fmt.Fprintf(os.Stderr,
					"warning: skipping Lambda %q: could not resolve its image digest: %v\n",
					f.FunctionName, err)
				continue
			}
			digest = resolvedImageDigest(out)
		} else {
			digest = decodeCodeSha256(f.CodeSha256)
		}

		if !isSHA256Hex(digest) {
			fmt.Fprintf(os.Stderr,
				"warning: skipping Lambda %q: no usable sha256 digest (package type %q)\n",
				f.FunctionName, f.PackageType)
			continue
		}
		arts = append(arts, map[string]string{"sha256": digest, "service_name": f.FunctionName})
	}
	return arts
}

// resolvedImageDigest pulls the image digest out of an `aws lambda get-function`
// response, from Code.ResolvedImageUri ("<repo>@sha256:<hex>").
func resolvedImageDigest(getFunctionOutput string) string {
	var gf struct {
		Code struct {
			ResolvedImageUri string `json:"ResolvedImageUri"`
			ImageUri         string `json:"ImageUri"`
		} `json:"Code"`
	}
	if err := json.Unmarshal([]byte(getFunctionOutput), &gf); err != nil {
		return ""
	}
	// Prefer the resolved URI; fall back to ImageUri only when it is itself
	// digest-pinned. A tag-pinned ImageUri tells us nothing about what is
	// actually running, so it is not a fallback -- it is a different question.
	for _, uri := range []string{gf.Code.ResolvedImageUri, gf.Code.ImageUri} {
		if _, after, found := strings.Cut(uri, "@sha256:"); found {
			return after
		}
	}
	return ""
}

// decodeCodeSha256 converts Lambda's base64 CodeSha256 to hex. A value that is
// already hex is returned unchanged, so both encodings work.
func decodeCodeSha256(s string) string {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return hex.EncodeToString(b)
	}
	return s
}
