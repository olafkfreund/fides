package main

import (
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// resolveImageDigest turns an image reference into the bare sha256 hex a
// snapshot will report for it.
//
// Approving an image previously meant reading a digest out of the cluster by
// hand -- `kubectl get pod -o jsonpath=...imageID`, then stripping the repo
// prefix and the sha256: -- which is both tedious and easy to get subtly wrong
// (#432).
//
// A reference that already carries a digest is returned as-is, with no network
// call: it is already the answer, and a lookup could only fail or lie.
//
// For a tag, this is the digest of whatever the registry serves for that tag,
// which for a multi-arch image is the INDEX digest. That is deliberate and it
// is the only correct choice here: containerd records the index digest in a
// pod's imageID, so that is the value a snapshot compares against. Resolving
// to a per-platform manifest digest would look more precise and would produce
// an approval that can never match anything running.
func resolveImageDigest(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", fmt.Errorf("empty image reference")
	}
	// Already digest-pinned — nothing to resolve.
	if _, after, found := strings.Cut(ref, "@sha256:"); found {
		if !isSHA256Hex(after) {
			return "", fmt.Errorf("%q has a malformed sha256 digest", ref)
		}
		return after, nil
	}
	if strings.Contains(ref, "@") {
		return "", fmt.Errorf("%q pins a digest algorithm Fides does not record (only sha256)", ref)
	}

	parsed, err := name.ParseReference(ref)
	if err != nil {
		return "", fmt.Errorf("parse %q: %w", ref, err)
	}
	desc, err := remote.Get(parsed, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", ref, err)
	}
	hex := desc.Digest.Hex
	if !isSHA256Hex(hex) {
		return "", fmt.Errorf("registry returned a digest that is not sha256 hex for %q", ref)
	}
	return hex, nil
}
