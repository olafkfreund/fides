// Package tsa anchors the tamper-evidence ledger to an external RFC3161
// Time-Stamp Authority (TSA). Timestamping a trail's chain head proves the head
// existed at a point in time, independently of the Fides database — so an
// auditor need not trust that Fides did not rewrite its own hash chain.
package tsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/digitorus/timestamp"
)

// LoadRoots reads a PEM bundle of trusted TSA CA certificates into a pool, so
// VerifyToken can require that a timestamp token chains to one of them. Returns
// (nil, nil) when pemPath is empty (root pinning disabled — signature-only).
func LoadRoots(pemPath string) (*x509.CertPool, error) {
	if pemPath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(pemPath) // #nosec G304 -- operator-configured trusted-roots bundle path
	if err != nil {
		return nil, fmt.Errorf("read tsa roots: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no certificates found in %s", pemPath)
	}
	return pool, nil
}

// imprint is the digest the TSA signs: sha256 of the chain-head hex string.
// RequestToken and VerifyToken must compute it identically.
func imprint(headHex string) [32]byte { return sha256.Sum256([]byte(headHex)) }

// ValidateURL guards the TSA endpoint against SSRF: it must be http(s) — many
// public TSAs use http, so https is not required — and must not resolve to a
// loopback, private, link-local, or cloud-metadata address.
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid tsa url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("tsa url must be http or https")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("tsa url has no host")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("tsa host does not resolve: %w", err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("tsa url resolves to a disallowed address (%s)", ip)
		}
	}
	return nil
}

// RequestToken asks an RFC3161 TSA to timestamp the given chain-head hash and
// returns the DER-encoded timestamp response. The response is validated before
// it is returned, so a stored token is always verifiable.
func RequestToken(ctx context.Context, tsaURL, headHex string, roots *x509.CertPool) ([]byte, error) {
	if err := ValidateURL(tsaURL); err != nil {
		return nil, err
	}
	reqDER, err := timestamp.CreateRequest(strings.NewReader(headHex), &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true, // ask the TSA to embed its cert so the token is self-verifiable
	})
	if err != nil {
		return nil, fmt.Errorf("build timestamp request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tsaURL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("tsa request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tsa returned status %d", resp.StatusCode)
	}
	if _, err := VerifyToken(body, headHex, roots); err != nil {
		return nil, fmt.Errorf("tsa response did not verify: %w", err)
	}
	return body, nil
}

// VerifyToken parses an RFC3161 timestamp response, verifies its signature (via
// the embedded TSA certificate) and that it timestamps exactly headHex, and
// returns the asserted time. A mismatching headHex — e.g. a tampered chain whose
// head no longer equals what was anchored — fails here.
//
// When roots is non-nil, the token's timestamping certificate must also chain to
// one of those trusted roots (root pinning); a self-signed or otherwise
// untrusted TSA cert is then rejected. With roots nil, only the token's own
// signature is checked (a valid signature by any embedded cert passes).
func VerifyToken(token []byte, headHex string, roots *x509.CertPool) (time.Time, error) {
	ts, err := timestamp.ParseResponse(token)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse timestamp: %w", err)
	}
	// The underlying parser only verifies the CMS signature when the token embeds
	// a certificate. Reject a token with none, or an unsigned/forged response
	// would be trusted (its signature is never checked).
	if len(ts.Certificates) == 0 {
		return time.Time{}, fmt.Errorf("timestamp token has no signing certificate (signature unverifiable)")
	}
	if ts.HashAlgorithm != crypto.SHA256 {
		return time.Time{}, fmt.Errorf("unexpected hash algorithm %v", ts.HashAlgorithm)
	}
	want := imprint(headHex)
	if !bytes.Equal(ts.HashedMessage, want[:]) {
		return time.Time{}, fmt.Errorf("timestamp imprint does not match chain head")
	}
	if roots != nil {
		if err := verifyChain(ts, roots); err != nil {
			return time.Time{}, err
		}
	}
	return ts.Time, nil
}

// verifyChain checks that the token's timestamping certificate chains to a
// trusted root with the timestamping extended key usage.
func verifyChain(ts *timestamp.Timestamp, roots *x509.CertPool) error {
	var leaf *x509.Certificate
	inter := x509.NewCertPool()
	for _, c := range ts.Certificates {
		isTS := false
		for _, eku := range c.ExtKeyUsage {
			if eku == x509.ExtKeyUsageTimeStamping {
				isTS = true
				break
			}
		}
		if isTS && leaf == nil {
			leaf = c
		} else {
			inter.AddCert(c)
		}
	}
	if leaf == nil {
		return fmt.Errorf("no timestamping certificate in token")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		CurrentTime:   ts.Time,
	}); err != nil {
		return fmt.Errorf("tsa certificate chain not trusted: %w", err)
	}
	return nil
}
