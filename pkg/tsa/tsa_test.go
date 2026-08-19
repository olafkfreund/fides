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
	bad := []string{
		"ftp://tsa.example.com",          // wrong scheme
		"http://127.0.0.1/tsa",           // loopback
		"https://169.254.169.254/latest", // cloud metadata (link-local)
		"http://localhost:318",           // loopback by name
		"not a url with spaces",
	}
	for _, u := range bad {
		if err := ValidateURL(u); err == nil {
			t.Errorf("ValidateURL(%q) = nil, want error", u)
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
