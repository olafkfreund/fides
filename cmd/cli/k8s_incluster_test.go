package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// k8sFakeServiceAccount stands up a TLS "API server" and the ServiceAccount
// mount a pod would see for it: the server's own certificate written out as the
// cluster CA, plus a token file. It repoints saTokenPath/saCAPath and the two
// kubelet-injected env vars at them for the duration of the test.
//
// This is what #512 unblocked. While those paths were consts, every case below
// stopped at the token read, so the CA pinning, the bearer header, the RBAC
// message and the read cap were all dark -- each carrying a #nosec comment
// asserting a security property that no test exercised.
func k8sFakeServiceAccount(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("fake-sa-token\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	// net.SplitHostPort, not a Cut on the first colon: httptest falls back to
	// an IPv6 loopback ("https://[::1]:34567") wherever 127.0.0.1 cannot be
	// bound, and splitting that on the first colon yields host="[" -- so every
	// test built on this helper would fail inside validAPIHostPort instead of
	// exercising the path it claims to.
	host, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("unexpected test server URL %q: %v", srv.URL, err)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", host)
	t.Setenv("KUBERNETES_SERVICE_PORT", port)

	// Restore what was saved rather than re-hardcoding the mount paths: if they
	// ever change in k8s.go, literals here would quietly rewrite the globals to
	// stale values for every later test in the package, and the failure would
	// surface a long way from this line.
	origToken, origCA := saTokenPath, saCAPath
	saTokenPath, saCAPath = tokenPath, caPath
	t.Cleanup(func() { saTokenPath, saCAPath = origToken, origCA })
	return srv
}

// The happy path, and the two properties that matter about it: the request is
// authenticated with the mounted token, and it goes to the namespaced path.
func TestFetchPodsInClusterSendsBearerTokenToNamespacedPath(t *testing.T) {
	var gotAuth, gotPath, gotAccept string
	k8sFakeServiceAccount(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotAccept = r.Header.Get("Authorization"), r.URL.Path, r.Header.Get("Accept")
		_, _ = w.Write([]byte(`{"items":[]}`))
	})

	body, err := fetchPodsInCluster("payments")
	if err != nil {
		t.Fatalf("fetchPodsInCluster: %v", err)
	}
	if string(body) != `{"items":[]}` {
		t.Errorf("body = %q", body)
	}
	// Trimmed: the file ends with a newline and it must not reach the header.
	if gotAuth != "Bearer fake-sa-token" {
		t.Errorf("Authorization = %q, want the trimmed mounted token", gotAuth)
	}
	if want := "/api/v1/namespaces/payments/pods"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q", gotAccept)
	}
}

// An empty namespace means all namespaces, a different path on the same client.
func TestFetchPodsInClusterAllNamespaces(t *testing.T) {
	var gotPath string
	k8sFakeServiceAccount(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"items":[]}`))
	})
	if _, err := fetchPodsInCluster(""); err != nil {
		t.Fatalf("fetchPodsInCluster: %v", err)
	}
	if gotPath != "/api/v1/pods" {
		t.Errorf("path = %q, want /api/v1/pods", gotPath)
	}
}

// An RBAC denial must surface the API server's own message: it names the verb
// and resource, which is the only thing that makes a misconfigured Role
// diagnosable from the reporter's logs.
func TestFetchPodsInClusterSurfacesRBACDenial(t *testing.T) {
	const denial = `pods is forbidden: User "system:serviceaccount:fides:reporter" cannot list resource "pods"`
	k8sFakeServiceAccount(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(denial))
	})

	_, err := fetchPodsInCluster("")
	if err == nil {
		t.Fatal("expected an error for a 403")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error = %v, want the status in it", err)
	}
	if !strings.Contains(err.Error(), "cannot list resource") {
		t.Errorf("error = %v, want the API server's own message preserved", err)
	}
	// It must not be the sentinel, or fetchPodsJSON would mask an RBAC problem
	// by falling back to a kubectl the reporter image does not contain.
	if errors.Is(err, errNotInCluster) {
		t.Error("an RBAC denial must not read as errNotInCluster")
	}
}

// A pod list over the cap must be a NAMED error, not a silent truncation.
//
// This test first asserted the truncating behaviour as correct, which locked in
// a real defect: reading exactly maxPodListBytes hands the caller a
// valid-length but syntactically broken JSON prefix with err == nil, and
// main.go then exits 1 with "Failed to parse pod list json" -- a size cap
// misdiagnosed as a corrupt API server, on the one cluster big enough to reach
// it. A test that pins the wrong behaviour is worse than no test.
func TestFetchPodsInClusterRejectsAnOversizeList(t *testing.T) {
	k8sFakeServiceAccount(t, func(w http.ResponseWriter, _ *http.Request) {
		chunk := strings.Repeat("a", 1<<20)
		for i := 0; i < 64; i++ {
			_, _ = w.Write([]byte(chunk))
		}
		_, _ = w.Write([]byte("OVERFLOW"))
	})

	body, err := fetchPodsInCluster("")
	if err == nil {
		t.Fatalf("expected an error past the cap, got %d bytes and nil", len(body))
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %v, want it to name the cap rather than surface as broken JSON", err)
	}
	if body != nil {
		t.Errorf("want no body alongside the error, got %d bytes", len(body))
	}
}

// A list exactly at the cap is still fine -- the limit is inclusive, and an
// off-by-one here would reject a legitimate response.
func TestFetchPodsInClusterAcceptsExactlyTheCap(t *testing.T) {
	k8sFakeServiceAccount(t, func(w http.ResponseWriter, _ *http.Request) {
		chunk := strings.Repeat("a", 1<<20)
		for i := 0; i < 64; i++ {
			_, _ = w.Write([]byte(chunk))
		}
	})

	body, err := fetchPodsInCluster("")
	if err != nil {
		t.Fatalf("a response exactly at the cap must be accepted: %v", err)
	}
	if len(body) != maxPodListBytes {
		t.Errorf("read %d bytes, want %d", len(body), maxPodListBytes)
	}
}

// The TLS config trusts ONLY the mounted cluster CA. That is the control that
// stops the ServiceAccount token being handed to a host that is not the API
// server, so a CA that does not match the server must fail the handshake --
// not fall back, not proceed.
func TestFetchPodsInClusterRejectsAServerTheMountedCADoesNotSign(t *testing.T) {
	k8sFakeServiceAccount(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[]}`))
	})

	// A syntactically valid CA that signed something else entirely. Generated
	// here rather than taken from a second httptest.NewTLSServer: every
	// httptest TLS server presents Go's one hardcoded internal certificate, so
	// a second server would hand back the SAME cert and the handshake would
	// (correctly) succeed, quietly turning this into a test of nothing.
	if err := os.WriteFile(saCAPath, k8sUnrelatedCAPEM(t), 0o600); err != nil {
		t.Fatalf("overwrite CA: %v", err)
	}

	_, err := fetchPodsInCluster("")
	if err == nil {
		t.Fatal("expected the handshake to fail against an untrusted server")
	}
	if !strings.Contains(err.Error(), "query API server") {
		t.Errorf("error = %v, want it wrapped as a query failure", err)
	}
}

// A CA file that is not PEM at all is a distinct, named failure rather than an
// opaque handshake error.
func TestFetchPodsInClusterRejectsAMalformedCA(t *testing.T) {
	k8sFakeServiceAccount(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[]}`))
	})
	if err := os.WriteFile(saCAPath, []byte("this is not a certificate"), 0o600); err != nil {
		t.Fatalf("overwrite CA: %v", err)
	}

	_, err := fetchPodsInCluster("")
	if err == nil {
		t.Fatal("expected an error for a non-PEM CA")
	}
	if !strings.Contains(err.Error(), "not valid PEM") {
		t.Errorf("error = %v, want it to name the malformed CA", err)
	}
}

// A missing CA beside a present token is a misconfigured pod, not a laptop.
func TestFetchPodsInClusterMissingCAIsARealError(t *testing.T) {
	k8sFakeServiceAccount(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[]}`))
	})
	if err := os.Remove(saCAPath); err != nil {
		t.Fatalf("remove CA: %v", err)
	}

	_, err := fetchPodsInCluster("")
	if !strings.Contains(errString(err), "read serviceaccount CA") {
		t.Errorf("error = %v, want it to name the CA read", err)
	}
	if errors.Is(err, errNotInCluster) {
		t.Error("a missing CA beside a present token must not read as errNotInCluster")
	}
}

// The distinction #512 asked for: an ABSENT token means "not a pod" and the
// caller falls back to kubectl; a token that exists but cannot be read is a
// misconfigured pod and must surface. Before this, both were the sentinel, so
// a broken projected volume silently reported "not in a cluster".
func TestFetchPodsInClusterDistinguishesAbsentFromUnreadableToken(t *testing.T) {
	k8sFakeServiceAccount(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[]}`))
	})

	t.Run("absent token means not in cluster", func(t *testing.T) {
		saved := saTokenPath
		saTokenPath = filepath.Join(t.TempDir(), "no-such-token")
		defer func() { saTokenPath = saved }()

		_, err := fetchPodsInCluster("")
		if !errors.Is(err, errNotInCluster) {
			t.Errorf("error = %v, want errNotInCluster so the caller falls back to kubectl", err)
		}
	})

	t.Run("unreadable token is a real error", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a 0000 file regardless of mode")
		}
		saved := saTokenPath
		p := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(p, []byte("x"), 0o000); err != nil {
			t.Fatalf("write token: %v", err)
		}
		saTokenPath = p
		defer func() { saTokenPath = saved }()

		_, err := fetchPodsInCluster("")
		if errors.Is(err, errNotInCluster) {
			t.Error("an unreadable token must NOT read as errNotInCluster — that is a misconfigured pod, and fetchPodsJSON would mask it by falling back to a kubectl the reporter image does not have")
		}
		if !strings.Contains(errString(err), "read serviceaccount token") {
			t.Errorf("error = %v, want it to name the token read", err)
		}
	})
}

// A tampered KUBERNETES_SERVICE_HOST must be rejected before any request goes
// out, because that request would carry the ServiceAccount token.
func TestFetchPodsInClusterRejectsATamperedHost(t *testing.T) {
	var hits int
	k8sFakeServiceAccount(t, func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"items":[]}`))
	})
	t.Setenv("KUBERNETES_SERVICE_HOST", "evil.example.com:8080/path")

	_, err := fetchPodsInCluster("")
	if err == nil {
		t.Fatal("expected a tampered host to be rejected")
	}
	if !strings.Contains(err.Error(), "KUBERNETES_SERVICE_HOST") {
		t.Errorf("error = %v, want it to name the offending variable", err)
	}
	if hits != 0 {
		t.Errorf("the token was sent somewhere: server saw %d request(s)", hits)
	}
}

// k8sUnrelatedCAPEM returns a self-signed certificate that signed nothing in
// this test, for asserting that an unrecognised CA is refused.
func k8sUnrelatedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
