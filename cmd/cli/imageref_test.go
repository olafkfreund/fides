package main

import (
	"strings"
	"testing"
)

const refDigest = "cb4e6a40d59b9dac61c9053dfa886c6024d707f812b2d64d20037f3aa5132a95"

// A reference that already carries a digest must be answered locally. Hitting
// the registry for it could only fail (network, auth, a deleted tag) or return
// something different from what the caller explicitly pinned -- and these tests
// run with no network, which is itself the assertion.
func TestResolveImageDigestShortCircuitsAPinnedReference(t *testing.T) {
	for _, ref := range []string{
		"ghcr.io/olafkfreund/fides-server@sha256:" + refDigest,
		"ghcr.io/olafkfreund/fides-server:0749209@sha256:" + refDigest,
		"  ghcr.io/org/app@sha256:" + refDigest + "  ",
	} {
		got, err := resolveImageDigest(ref)
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		if got != refDigest {
			t.Errorf("%s -> %q, want the bare hex digest", ref, got)
		}
	}
}

// A digest-shaped thing that is not a digest must be refused rather than
// forwarded to the API, where it would become an approval that can never match
// anything -- the #406/#430 failure mode.
func TestResolveImageDigestRejectsMalformedInput(t *testing.T) {
	for name, ref := range map[string]string{
		"empty":            "",
		"whitespace":       "   ",
		"truncated digest": "ghcr.io/org/app@sha256:cb4e6a40",
		"non-hex digest":   "ghcr.io/org/app@sha256:" + strings.Repeat("z", 64),
		"other algorithm":  "ghcr.io/org/app@sha512:" + strings.Repeat("a", 64),
	} {
		if got, err := resolveImageDigest(ref); err == nil {
			t.Errorf("%s: accepted %q -> %q, want an error", name, ref, got)
		}
	}
}

// A tag is resolved over the network, so this only pins that an unparseable
// reference fails before any request is attempted.
func TestResolveImageDigestRejectsUnparseableReference(t *testing.T) {
	if _, err := resolveImageDigest("NOT A REFERENCE!!"); err == nil {
		t.Error("expected a parse error for an invalid reference")
	} else if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should name the parse failure, got %v", err)
	}
}
