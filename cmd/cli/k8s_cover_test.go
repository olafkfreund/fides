package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// isSHA256Hex must accept exactly a 64-char hex digest and reject anything
// shorter, longer, or containing non-hex characters -- this is the guard for
// the #430 bug where a truncated image TAG was mistaken for a digest.
func TestIsSHA256Hex(t *testing.T) {
	cases := []struct {
		name string
		s    string
		want bool
	}{
		{"valid lowercase", strings.Repeat("a", 64), true},
		{"valid uppercase", strings.Repeat("F", 64), true},
		{"valid mixed digits", strings.Repeat("a1B2", 16), true},
		{"too short", strings.Repeat("a", 63), false},
		{"too long", strings.Repeat("a", 65), false},
		{"empty", "", false},
		{"non-hex char", strings.Repeat("a", 63) + "z", false},
		{"right length but a tag-shaped separator", strings.Repeat("a", 63) + "-", false},
	}
	for _, c := range cases {
		if got := isSHA256Hex(c.s); got != c.want {
			t.Errorf("%s: isSHA256Hex(%q) = %v, want %v", c.name, c.s, got, c.want)
		}
	}
}

// With host/port set but no mounted ServiceAccount token (true of any
// environment outside a real pod, including this test), fetchPodsInCluster
// must still report errNotInCluster rather than some other failure -- that
// sentinel is what routes callers to the kubectl fallback.
func TestFetchPodsInClusterHostSetButNoToken(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	// Point at a path that certainly does not exist rather than relying on the
	// real mount being absent. Run this suite inside a pod -- an ARC
	// self-hosted runner, the k3d dev container -- and the token IS there, so
	// this would dial 10.0.0.1:443 and block on the client's 60s timeout before
	// failing. That non-hermeticity is what #512 was about; saTokenPath is a
	// var now, so there is no reason left to depend on the host.
	orig := saTokenPath
	saTokenPath = filepath.Join(t.TempDir(), "absent-token")
	defer func() { saTokenPath = orig }()

	_, err := fetchPodsInCluster("")
	if !errors.Is(err, errNotInCluster) {
		t.Fatalf("want errNotInCluster when no ServiceAccount token is mounted, got %v", err)
	}
}

// fetchPodsJSON must fall back to kubectl off-cluster. This process is not
// in-cluster, so it always takes that branch; kubectl itself may or may not
// be configured with a reachable cluster, so only the routing is asserted.
func TestFetchPodsJSONFallsBackOffCluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	_, err := fetchPodsJSON("")
	if err != nil && !strings.Contains(err.Error(), "kubectl") {
		t.Errorf("off-cluster error = %v, want it to come from the kubectl fallback", err)
	}
}

// fetchPodsViaKubectl must pass the namespace as a separate argument (never
// shell-interpolated) and report a wrapped error when kubectl itself fails,
// rather than panicking or silently returning nothing. Point KUBECONFIG at a
// file that cannot exist so this is deterministic regardless of what cluster
// (if any) is otherwise configured on the machine running the test.
func TestFetchPodsViaKubectlWrapsError(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig-for-fides-cover-test.yaml")

	_, err := fetchPodsViaKubectl("some-namespace")
	if err == nil {
		t.Fatal("expected an error with an unreachable KUBECONFIG")
	}
	if !strings.Contains(err.Error(), "kubectl") {
		t.Errorf("error = %v, want it wrapped with \"kubectl: ...\"", err)
	}
}

// The namespace-scoped and all-namespaces forms build different kubectl
// argument lists; both must be exercised.
func TestFetchPodsViaKubectlNamespaceForms(t *testing.T) {
	t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig-for-fides-cover-test.yaml")

	if _, err := fetchPodsViaKubectl(""); err == nil {
		t.Fatal("expected an error with an unreachable KUBECONFIG (all-namespaces form)")
	}
	if _, err := fetchPodsViaKubectl("some-namespace"); err == nil {
		t.Fatal("expected an error with an unreachable KUBECONFIG (namespace-scoped form)")
	}
}
