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
	"syscall"
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

// disallowedIP reports whether an address is one the TSA client must never
// connect to: loopback, private, link-local (which covers the cloud metadata
// endpoint at 169.254.169.254), or unspecified.
//
// ponytail: carrier-grade NAT (100.64.0.0/10) is deliberately not blocked,
// though Alibaba's metadata service lives at 100.100.100.200. That range is
// also where Tailscale puts its nodes, so blocking it would break an operator
// running an internal TSA over a tailnet — a real configuration, against a
// metadata service on a cloud Fides does not currently target. Revisit if
// Alibaba support lands.
func disallowedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// Configured returns the TSA endpoints an operator has set, in the order
// FIDES_TSA_URL then FIDES_TSA_URLS.
func Configured() []string {
	var out []string
	seen := map[string]bool{}
	add := func(raw string) {
		if raw = strings.TrimSpace(raw); raw != "" && !seen[raw] {
			seen[raw] = true
			out = append(out, raw)
		}
	}
	add(os.Getenv("FIDES_TSA_URL"))
	for _, u := range strings.Split(os.Getenv("FIDES_TSA_URLS"), ",") {
		add(u)
	}
	return out
}

// Resolve turns a caller's choice of TSA into one of the configured endpoints,
// and returns the **configured** string rather than the caller's.
//
// That substitution is the point, not a detail. tsa_url arrives in an API
// request body, so before this the destination was chosen by the caller and
// every guard downstream was trying to constrain a value it did not trust: the
// dial guard stopped it reaching an internal address, a host allowlist stopped
// it naming an unexpected host, and the path, query and userinfo were still
// whatever was sent. Matching and then using our own copy ends that — what
// reaches the network is a string an operator configured, and the request only
// selects among them.
//
// An empty choice means the first configured endpoint, so a caller that does
// not care keeps working unchanged.
func Resolve(requested string) (string, error) {
	configured := Configured()
	if len(configured) == 0 {
		return "", fmt.Errorf("no TSA is configured: set FIDES_TSA_URL, or FIDES_TSA_URLS " +
			"to the endpoints callers may choose between")
	}
	if strings.TrimSpace(requested) == "" {
		return configured[0], nil
	}
	want := strings.TrimSpace(requested)
	for _, c := range configured {
		if strings.EqualFold(c, want) {
			return c, nil
		}
	}
	return "", fmt.Errorf("tsa_url %q is not one of this server's configured endpoints; "+
		"add it to FIDES_TSA_URLS if callers should be able to choose it", want)
}

// ValidateURL guards the TSA endpoint against SSRF: it must be http(s) — many
// public TSAs use http, so https is not required — and must not resolve to a
// loopback, private, link-local, or cloud-metadata address.
//
// This is an early, friendly error and NOT the security boundary. It cannot be,
// because it resolves the host and the HTTP client then resolves it again: a
// name answering with a public address here and 169.254.169.254 there walks
// straight through (DNS rebinding). The boundary is safeClient's dial guard,
// which checks the address actually being connected to.
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
		if disallowedIP(ip) {
			return fmt.Errorf("tsa url resolves to a disallowed address (%s)", ip)
		}
	}
	return nil
}

// safeClient returns the HTTP client used to talk to a TSA. The endpoint comes
// from an API request body, so it is attacker-chosen and the client has to hold
// the SSRF boundary itself.
//
// The check lives in Dialer.Control because that is the one place that sees the
// address actually being connected to, after resolution. Validating the URL
// before the request cannot hold, for two reasons:
//
//   - Redirects are not validated at all. net/http follows up to 10 by default,
//     so a TSA answering 302 to http://169.254.169.254/ is enough to reach the
//     metadata service with the initial URL looking perfectly legitimate.
//   - The pre-flight lookup and the client's own lookup are separate calls, so a
//     hostname under the caller's control can answer with a public address for
//     the first and an internal one for the second.
//
// Every connection goes through Control, redirect hops included, so both close
// together. CheckRedirect is kept as well: it turns the refusal into an error
// naming the redirect rather than an opaque dial failure.
func safeClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("tsa address %q: %w", address, err)
			}
			// Already an IP literal: Control runs after resolution.
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("tsa address %q is not an IP", address)
			}
			if disallowedIP(ip) {
				return fmt.Errorf("tsa url resolves to a disallowed address (%s)", ip)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("tsa redirected too many times")
			}
			if err := ValidateURL(req.URL.String()); err != nil {
				return fmt.Errorf("tsa redirect to %s: %w", req.URL.Redacted(), err)
			}
			return nil
		},
	}
}

// newTSAClient is the seam that lets a test assert RequestToken actually uses
// the guarded client, and it exists for no other reason — it is not a
// configuration point and nothing outside tests reassigns it.
//
// The seam is here because the property cannot be tested from the outside.
// Reaching the dial guard through RequestToken needs a host that resolves to a
// public address for ValidateURL and an internal one for the client, i.e. DNS
// rebinding, i.e. an in-process DNS server. Without it, replacing this call
// with a plain http.Client silently reinstates the SSRF that #454 closed, and
// every test still passes — which was the one mutation that survived there.
var newTSAClient = safeClient

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
	client := newTSAClient()
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
