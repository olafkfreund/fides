package main

import (
	"strings"
	"testing"
)

// A syntactically valid tag reference must parse and then go to the registry.
// resolveImageDigest wraps the two failure modes differently -- `parse %q` when
// name.ParseReference rejects the string, `resolve %q` when remote.Get fails --
// so asserting on which wrapper comes back is what pins that a parseable
// reference actually reached the registry call.
//
// Pointed at 127.0.0.1:1 rather than a real registry deliberately. An earlier
// version of this test used ghcr.io and skipped itself when the registry was
// reachable, which meant it asserted nothing at all in CI (where there is
// always network) and only did real work on a disconnected laptop -- exactly
// backwards. Port 1 on loopback refuses instantly, needs no network, and gives
// the same answer everywhere.
func TestResolveImageDigestParseableTagReachesRegistry(t *testing.T) {
	_, err := resolveImageDigest("127.0.0.1:1/library/alpine:latest")
	if err == nil {
		t.Fatal("expected a registry failure against a closed port, got nil")
	}
	if !strings.Contains(err.Error(), "resolve") {
		t.Errorf("error = %v, want it wrapped with \"resolve ...\" (i.e. it got past parsing)", err)
	}
}

// A bare, unqualified name is still a parseable reference (it defaults to
// docker.io/library), so it must never come back as a parse error. Whether the
// registry answers depends on the network, so this asserts on both outcomes
// rather than skipping one: resolving proves it parsed, and a failure must be a
// "resolve" failure rather than a "parse" one.
func TestResolveImageDigestBareNameIsParseable(t *testing.T) {
	hex, err := resolveImageDigest("alpine")
	if err == nil {
		if !isSHA256Hex(hex) {
			t.Errorf("resolved digest %q is not sha256 hex", hex)
		}
		return
	}
	if strings.Contains(err.Error(), "parse ") {
		t.Errorf("error = %v, want a bare name to parse (it defaults to docker.io/library)", err)
	}
	if !strings.Contains(err.Error(), "resolve") {
		t.Errorf("error = %v, want it wrapped with \"resolve ...\"", err)
	}
}
