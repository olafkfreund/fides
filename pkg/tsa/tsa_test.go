package tsa

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

// mintToken builds a valid RFC3161 timestamp response over headHex using a
// throwaway self-signed TSA certificate — no live network needed.
func mintToken(t *testing.T, headHex string) []byte {
	tok, _ := mintTokenOpts(t, headHex, true)
	return tok
}

// mintTokenOpts returns the timestamp response and the self-signed TSA cert it
// was signed with (so tests can build a trusted-roots pool from it).
func mintTokenOpts(t *testing.T, headHex string, embedCert bool) ([]byte, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test TSA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	digest := sha256.Sum256([]byte(headHex))
	ts := &timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     digest[:],
		Time:              time.Now(),
		SerialNumber:      big.NewInt(42),
		Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1}, // required TSTInfo policy OID
		Certificates:      []*x509.Certificate{cert},
		AddTSACertificate: embedCert,
	}
	resp, err := ts.CreateResponse(cert, key)
	if err != nil {
		t.Fatalf("create response: %v", err)
	}
	return resp, cert
}

func TestVerifyToken(t *testing.T) {
	const head = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	token := mintToken(t, head)

	// Valid: the token verifies against the head it was minted over.
	got, err := VerifyToken(token, head, nil)
	if err != nil {
		t.Fatalf("VerifyToken valid case: %v", err)
	}
	if got.IsZero() {
		t.Fatal("expected a non-zero timestamp")
	}

	// Tamper: a chain whose head changed no longer matches the anchor.
	if _, err := VerifyToken(token, "deadbeef", nil); err == nil {
		t.Fatal("expected verification to FAIL for a tampered/mismatched head")
	}

	// Garbage token must not parse.
	if _, err := VerifyToken([]byte("not a timestamp response"), head, nil); err == nil {
		t.Fatal("expected parse failure for a garbage token")
	}
}

// A token that embeds no signing certificate must be rejected: the underlying
// parser skips signature verification when no cert is present, so accepting it
// would trust an unsigned/forged response.
func TestVerifyTokenRejectsCertlessToken(t *testing.T) {
	const head = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	token, _ := mintTokenOpts(t, head, false) // AddTSACertificate=false -> no embedded cert
	if _, err := VerifyToken(token, head, nil); err == nil {
		t.Fatal("expected verification to FAIL for a token with no signing certificate")
	}
}

// TestVerifyTokenRootPinning verifies that, when trusted roots are supplied, a
// token is accepted only if its cert chains to one of them.
func TestVerifyTokenRootPinning(t *testing.T) {
	const head = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	token, cert := mintTokenOpts(t, head, true)

	// Trusted: roots containing the signing cert -> chain verifies.
	trusted := x509.NewCertPool()
	trusted.AddCert(cert)
	if _, err := VerifyToken(token, head, trusted); err != nil {
		t.Fatalf("expected trusted roots to verify: %v", err)
	}

	// Untrusted: a roots pool with a DIFFERENT cert -> rejected.
	_, other := mintTokenOpts(t, head, true)
	untrusted := x509.NewCertPool()
	untrusted.AddCert(other)
	if _, err := VerifyToken(token, head, untrusted); err == nil {
		t.Fatal("expected verification to FAIL when the cert does not chain to a trusted root")
	}

	// nil roots -> signature-only, still passes (backward compatible).
	if _, err := VerifyToken(token, head, nil); err != nil {
		t.Fatalf("nil roots should verify signature-only: %v", err)
	}
}

func TestValidateURL(t *testing.T) {
	// Every one of these hosts is allowlisted on purpose. Without that they
	// would be refused for not being configured, and this test would pass
	// whatever happened to the scheme and address rules it exists to check —
	// deleting disallowedIP outright would not have failed it.
	t.Setenv("FIDES_TSA_ALLOWED_HOSTS", "127.0.0.1, 169.254.169.254, localhost, tsa.example.com")

	for _, tc := range []struct{ url, because string }{
		{"ftp://tsa.example.com", "must be http or https"},
		{"http://127.0.0.1/tsa", "disallowed address"},
		{"https://169.254.169.254/latest", "disallowed address"},
		{"http://localhost:318", "disallowed address"},
		{"not a url with spaces", "must be http or https"}, // no scheme, so it fails there first
	} {
		err := ValidateURL(tc.url)
		if err == nil {
			t.Errorf("ValidateURL(%q) = nil, want error", tc.url)
			continue
		}
		if !strings.Contains(err.Error(), tc.because) {
			t.Errorf("ValidateURL(%q) failed with %q, want it to mention %q",
				tc.url, err, tc.because)
		}
	}
}

// dialGuard runs the TSA client's dial guard against an already-resolved
// address, which is the form Dialer.Control receives. A short timeout keeps a
// permitted address from actually opening a connection: what matters is whether
// the guard refused, not whether the host answered.
func dialGuard(t *testing.T, address string) error {
	t.Helper()
	tr, ok := safeClient().Transport.(*http.Transport)
	if !ok || tr.DialContext == nil {
		t.Fatal("the TSA client has no custom dialer, so nothing checks the resolved address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := tr.DialContext(ctx, "tcp", address)
	return err
}

// The dial guard is the SSRF boundary, so it is tested against the address the
// client actually connects to rather than the URL the caller supplied.
// ValidateURL cannot hold that boundary: it resolves the host once and the HTTP
// client resolves it again, and it never sees a redirect target at all.
func TestDialGuardRefusesInternalAddresses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		refused bool
	}{
		// The one that matters: an SSRF reaching this returns cloud credentials.
		{"the cloud metadata endpoint", "169.254.169.254:80", true},
		{"loopback", "127.0.0.1:80", true},
		{"IPv6 loopback", "[::1]:80", true},
		{"a private network", "10.0.0.5:80", true},
		{"another private range", "192.168.1.1:80", true},
		{"the unspecified address", "0.0.0.0:80", true},
		// Not refused, or the guard would block every real TSA. Asserted on the
		// refusal message rather than on success, so the test does not need the
		// host to be reachable from wherever it runs.
		{"a public address", "8.8.8.8:80", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := dialGuard(t, tc.address)
			blocked := err != nil && strings.Contains(err.Error(), "disallowed")
			if tc.refused && !blocked {
				t.Errorf("connecting to %s was not refused by the guard (err = %v)", tc.address, err)
			}
			if !tc.refused && blocked {
				t.Errorf("connecting to %s was refused: %v", tc.address, err)
			}
		})
	}
}

// A TSA answering with a redirect must not be followed to an internal address.
// This is the bypass that needs no DNS control at all: net/http follows
// redirects by default and the pre-flight URL check never sees them, so a 302
// to the metadata service was enough to reach it.
func TestTSARedirectToAnInternalAddressIsRefused(t *testing.T) {
	// Stands in for the metadata service. It must never be reached.
	var reached bool
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		_, _ = w.Write([]byte("credentials"))
	}))
	defer internal.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL, http.StatusFound)
	}))
	defer redirector.Close()

	// safeClient directly rather than RequestToken: both servers are on
	// loopback, so RequestToken's pre-flight ValidateURL would refuse the first
	// URL and the redirect would never be exercised. What is under test is
	// whether the client follows a redirect to an internal address.
	resp, err := safeClient().Get(redirector.URL)
	if err == nil {
		defer resp.Body.Close()
	}
	if reached {
		t.Error("the client followed a redirect to an internal address — this is the SSRF")
	}
	if err == nil {
		t.Error("following a redirect to an internal address returned no error")
	}
}

// RequestToken must obtain its client from safeClient.
//
// This is the mutation that survived #454: the guard tests all call safeClient
// directly, so replacing this one call site with a plain &http.Client{} would
// reinstate the SSRF — redirects to the metadata service and all — while every
// other test in this file still passed. The property cannot be observed from
// outside the package (reaching the dial guard through RequestToken needs DNS
// rebinding), so it is pinned at the seam instead.
func TestRequestTokenUsesTheGuardedClient(t *testing.T) {
	original := newTSAClient
	t.Cleanup(func() { newTSAClient = original })

	var built int
	newTSAClient = func() *http.Client {
		built++
		c := original()
		// Assert the default factory returns a guarded client, not merely that
		// it was called. Without this, repointing newTSAClient at a bare
		// &http.Client{} passes: the call happens, and nothing looks at what
		// comes back.
		tr, ok := c.Transport.(*http.Transport)
		if !ok || tr.DialContext == nil {
			t.Error("the TSA client has no custom dialer, so nothing checks the resolved address")
		}
		if c.CheckRedirect == nil {
			t.Error("the TSA client does not check redirects, so a 302 to an internal address is followed")
		}
		return c
	}

	// TEST-NET-3 (RFC 5737): a public address, so ValidateURL lets it through
	// and the client is constructed, but one that never answers. The context
	// deadline ends the attempt — what is asserted is that a client was built
	// by the factory, not what the request returned.
	// Allowlisted so the request reaches the point of building a client;
	// ValidateURL now refuses a host the operator never named.
	t.Setenv("FIDES_TSA_ALLOWED_HOSTS", "203.0.113.1")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, _ = RequestToken(ctx, "http://203.0.113.1/tsa", "abc123", nil)

	if built == 0 {
		t.Fatal("RequestToken built its own HTTP client instead of the guarded one — " +
			"the SSRF dial guard is not on the request path")
	}
}

// The destination has to be one the operator named.
//
// The dial guard stops a request reaching an internal address however the name
// resolves. It does not stop a caller pointing Fides at a host they control on
// the public internet — and tsa_url arrives in an API request body, so without
// an allowlist the destination is attacker-chosen.
func TestOnlyConfiguredTSAHostsAreAllowed(t *testing.T) {
	for _, tc := range []struct {
		name        string
		tsaURL      string
		allowedList string
		target      string
		wantErr     string
	}{
		{
			name:   "the server's own TSA is always allowed",
			tsaURL: "https://timestamp.example/tsa", target: "https://timestamp.example/tsa",
		},
		{
			name:   "a host the operator did not name is refused",
			tsaURL: "https://timestamp.example/tsa", target: "https://attacker.example/collect",
			wantErr: "not allowed",
		},
		{
			name:        "an extra host may be named",
			allowedList: "one.example, two.example",
			target:      "https://two.example/tsa",
		},
		{
			name:        "matching ignores case, because hostnames do",
			allowedList: "One.Example",
			target:      "https://ONE.example/tsa",
		},
		{
			name: "with nothing configured, nothing is allowed",
			// Rather than everything: an unconfigured server refuses to anchor
			// anyway, so the permissive reading would only ever help an
			// attacker.
			target: "https://anything.example/tsa", wantErr: "no tsa hosts are configured",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("FIDES_TSA_URL", tc.tsaURL)
			t.Setenv("FIDES_TSA_ALLOWED_HOSTS", tc.allowedList)

			err := ValidateURL(tc.target)
			if tc.wantErr == "" {
				// It may still fail on DNS — these hosts do not resolve — but
				// it must not fail on the allowlist.
				if err != nil && strings.Contains(err.Error(), "allowed") {
					t.Errorf("refused a configured host: %v", err)
				}
				if err != nil && strings.Contains(err.Error(), "no tsa hosts") {
					t.Errorf("refused with nothing configured, but a host was: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("%s was permitted", tc.target)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}
