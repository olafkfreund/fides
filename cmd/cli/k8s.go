package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Standard in-cluster ServiceAccount mount. Kubernetes projects the token and
// the API server's CA here in every pod that has a ServiceAccount.
const (
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- well-known mount path, not a credential
	saCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	// The pod list of a large cluster is big but not unbounded. Cap it so a
	// hostile or broken API server cannot make the reporter allocate freely.
	maxPodListBytes = 64 << 20 // 64 MiB
)

// errNotInCluster means no ServiceAccount was mounted, so this is not running
// as a pod. Callers fall back to kubectl (which reads a kubeconfig).
var errNotInCluster = errors.New("not running in-cluster")

// fetchPodsJSON returns the API server's PodList JSON, restricted to one
// namespace when ns is non-empty.
//
// In-cluster (the k8s-reporter CronJob, which is the only thing shipped as an
// image) this talks to the API server directly over HTTPS with the mounted
// ServiceAccount token. That is the whole reason kubectl used to be baked into
// Dockerfile.reporter -- a ~50MB third-party binary carrying 24 fixable
// HIGH/CRITICAL CVEs in ITS vendored deps, which we could not patch and had to
// except by path from the Trivy gates (#398).
//
// Deliberately NOT client-go: this needs exactly one read, the caller already
// parses PodList with encoding/json, and client-go would pull ~100 modules
// including its own golang.org/x/net -- relocating the CVE surface rather than
// removing it. net/http + the mounted CA is the whole client.
//
// Outside a cluster (a developer laptop) there is no ServiceAccount, so it
// falls back to kubectl and its kubeconfig -- context, exec auth plugins and
// all. That path is unchanged; kubectl is simply no longer in the image.
func fetchPodsJSON(ns string) ([]byte, error) {
	body, err := fetchPodsInCluster(ns)
	if err == nil {
		return body, nil
	}
	if !errors.Is(err, errNotInCluster) {
		// A mounted ServiceAccount that fails to read is a real error (RBAC,
		// expired token, unreachable API server). Falling back to kubectl here
		// would mask it, and in the reporter image there is no kubectl to fall
		// back to anyway.
		return nil, err
	}
	return fetchPodsViaKubectl(ns)
}

// podsPath builds the API path for a pod list. The namespace comes from a
// --flag and lands in a URL path, so it is escaped: an unescaped value like
// "a/../../../secrets" would otherwise walk to a different API entirely.
func podsPath(ns string) string {
	if ns == "" {
		return "/api/v1/pods"
	}
	return "/api/v1/namespaces/" + neturl.PathEscape(ns) + "/pods"
}

// validAPIHostPort accepts only what the kubelet actually injects: an IP or a
// plain hostname, and a numeric port. Anything else means the environment was
// tampered with, and this request carries a ServiceAccount token.
func validAPIHostPort(host, port string) error {
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("KUBERNETES_SERVICE_PORT %q is not a valid port", port)
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	// Hostname form: dot-separated DNS labels, nothing that could smuggle a
	// credential, a port, a path or a second host into the URL.
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return fmt.Errorf("KUBERNETES_SERVICE_HOST %q is not a valid host", host)
		}
		for _, r := range label {
			ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-'
			if !ok {
				return fmt.Errorf("KUBERNETES_SERVICE_HOST %q is not a valid host", host)
			}
		}
	}
	return nil
}

func fetchPodsInCluster(ns string) ([]byte, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errNotInCluster
	}
	token, err := os.ReadFile(saTokenPath)
	if err != nil {
		return nil, errNotInCluster
	}
	caPEM, err := os.ReadFile(saCAPath)
	if err != nil {
		return nil, fmt.Errorf("read serviceaccount CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("serviceaccount CA at %s is not valid PEM", saCAPath)
	}

	// KUBERNETES_SERVICE_HOST/PORT are injected by the kubelet, but they are
	// still environment input, so validate rather than trust: a host that is
	// neither an IP nor a plain hostname, or a non-numeric port, would let a
	// tampered environment point this request somewhere else with the
	// ServiceAccount token attached.
	if err := validAPIHostPort(host, port); err != nil {
		return nil, err
	}
	endpoint := "https://" + net.JoinHostPort(host, port) + podsPath(ns)

	// #nosec G704 -- not SSRF: scheme is a hardcoded https literal, host/port are
	// validated above, the namespace is PathEscape'd into the path only, and the
	// TLS config below trusts ONLY the mounted cluster CA -- a redirected host
	// cannot present an acceptable cert, so the token is never sent elsewhere.
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Do(req) // #nosec G704 -- see the justification on http.NewRequest above

	if err != nil {
		return nil, fmt.Errorf("query API server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPodListBytes))
	if err != nil {
		return nil, fmt.Errorf("read pod list: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Surface the API server's own message: an RBAC denial names the verb
		// and resource, which is what makes a misconfigured Role diagnosable.
		return nil, fmt.Errorf("API server returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func fetchPodsViaKubectl(ns string) ([]byte, error) {
	args := []string{"get", "pods", "-A", "-o", "json"}
	if ns != "" {
		args = []string{"get", "pods", "-n", ns, "-o", "json"}
	}
	out, err := exec.Command("kubectl", args...).Output() // #nosec G204 -- fixed subcommand; namespace passed as a distinct arg, never shell-interpolated
	if err != nil {
		return nil, fmt.Errorf("kubectl: %w", err)
	}
	return out, nil
}
