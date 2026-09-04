package main

import (
	"strings"
	"testing"
)

// A syntactically valid tag reference must parse successfully and then go to
// the registry -- which, with no network reachable in this sandbox, fails.
// This pins that a *parseable* reference reaches remote.Get (rather than
// being rejected early) and that a registry failure is reported wrapped with
// "resolve", not silently swallowed or panicking.
func TestResolveImageDigestParseableTagReachesRegistry(t *testing.T) {
	_, err := resolveImageDigest("ghcr.io/olafkfreund/fides-server:latest")
	if err == nil {
		t.Skip("registry reachable in this environment; nothing to assert")
	}
	if !strings.Contains(err.Error(), "resolve") {
		t.Errorf("error = %v, want it wrapped with \"resolve ...\" (i.e. it reached the registry call)", err)
	}
}

// A bare, unqualified name is still a parseable reference (defaults to
// docker.io/library), so it must also reach the registry call rather than
// being rejected as malformed.
func TestResolveImageDigestBareNameIsParseable(t *testing.T) {
	_, err := resolveImageDigest("alpine")
	if err == nil {
		t.Skip("registry reachable in this environment; nothing to assert")
	}
	if !strings.Contains(err.Error(), "resolve") {
		t.Errorf("error = %v, want it wrapped with \"resolve ...\"", err)
	}
}
