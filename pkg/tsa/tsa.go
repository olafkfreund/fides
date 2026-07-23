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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/digitorus/timestamp"
)

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
func RequestToken(ctx context.Context, tsaURL, headHex string) ([]byte, error) {
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
	if _, err := VerifyToken(body, headHex); err != nil {
		return nil, fmt.Errorf("tsa response did not verify: %w", err)
	}
	return body, nil
}

// VerifyToken parses an RFC3161 timestamp response, verifies its signature (via
// the embedded TSA certificate) and that it timestamps exactly headHex, and
// returns the asserted time. A mismatching headHex — e.g. a tampered chain whose
// head no longer equals what was anchored — fails here.
func VerifyToken(token []byte, headHex string) (time.Time, error) {
	ts, err := timestamp.ParseResponse(token)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse timestamp: %w", err)
	}
	// The underlying parser only verifies the CMS signature when the token embeds
	// a certificate. Reject a token with none, or an unsigned/forged response
	// would be trusted (its signature is never checked). Chaining that cert to a
	// pinned trusted root is the remaining hardening (see package docs).
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
	return ts.Time, nil
}
