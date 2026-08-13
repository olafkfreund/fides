package main

import (
	"errors"
	"testing"
)

// The namespace reaches the API server as a URL path segment, so a value
// containing slashes must not be able to redirect the request to another API.
func TestPodsPath(t *testing.T) {
	cases := []struct {
		ns, want string
	}{
		{"", "/api/v1/pods"},
		{"fides", "/api/v1/namespaces/fides/pods"},
		{"a/../../../secrets", "/api/v1/namespaces/a%2F..%2F..%2F..%2Fsecrets/pods"},
	}
	for _, c := range cases {
		if got := podsPath(c.ns); got != c.want {
			t.Errorf("podsPath(%q) = %q, want %q", c.ns, got, c.want)
		}
	}
}

// The API server host/port come from the environment and the request carries a
// ServiceAccount token, so anything that could redirect it must be rejected.
func TestValidAPIHostPort(t *testing.T) {
	good := [][2]string{
		{"10.96.0.1", "443"},
		{"kubernetes.default.svc", "443"},
		{"fd00::1", "6443"},
	}
	for _, c := range good {
		if err := validAPIHostPort(c[0], c[1]); err != nil {
			t.Errorf("validAPIHostPort(%q, %q) = %v, want nil", c[0], c[1], err)
		}
	}
	bad := [][2]string{
		{"evil.com/path", "443"},   // path smuggling
		{"user@evil.com", "443"},   // credential smuggling
		{"evil.com:1234", "443"},   // second port
		{"kubernetes.default", ""}, // no port
		{"kubernetes.default", "notaport"},
		{"kubernetes.default", "99999"},
		{"kubernetes..default", "443"}, // empty label
	}
	for _, c := range bad {
		if err := validAPIHostPort(c[0], c[1]); err == nil {
			t.Errorf("validAPIHostPort(%q, %q) = nil, want error", c[0], c[1])
		}
	}
}

// Off-cluster there is no ServiceAccount, and the caller must get
// errNotInCluster specifically -- that sentinel is what routes to the kubectl
// fallback. Any other error means "in-cluster but broken" (RBAC, expired
// token) and must NOT be masked by falling back.
func TestFetchPodsInClusterOffCluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	if _, err := fetchPodsInCluster(""); !errors.Is(err, errNotInCluster) {
		t.Fatalf("want errNotInCluster off-cluster, got %v", err)
	}
}
