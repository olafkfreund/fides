// Package cosignverify verifies Sigstore/cosign container image signatures —
// keyless (Fulcio short-lived certificate + OIDC identity, anchored in the
// Rekor transparency log) or key-based (a long-lived public key) — and
// produces a normalized Verdict suitable for recording as a
// `cosign-verification` Fides attestation and for gating a deploy on.
//
// Signatures are resolved one of two ways:
//
//   - Options.Image set: the signature is fetched from the registry using
//     cosign's <repo>:sha256-<digest>.sig convention and converted to a
//     Sigstore bundle. A bare digest cannot identify an OCI repository, which
//     is why the repo has to be named rather than inferred (#407).
//   - Options.BundlePath set: a pre-fetched bundle (e.g. from
//     `cosign verify --bundle out.json`) is used as-is. Still the right choice
//     offline or air-gapped.
//
// Verify returns ErrBundleRequired when neither is supplied.
package cosignverify

import (
	"context"
	"errors"
)

// ErrBundleRequired is returned when no verification bundle is available and
// registry auto-discovery has not been implemented yet (see package doc).
var ErrBundleRequired = errors.New("cosignverify: no signature source; pass --image <repo> to resolve it from the registry, or --bundle <path> to use a pre-fetched bundle")

// Verdict is the normalized result of a single image verification. It is
// recorded as the payload of a `cosign-verification` attestation.
type Verdict struct {
	Verified bool   `json:"verified"`
	Digest   string `json:"digest"`
	Method   string `json:"method"` // "keyless" | "key"
	Signer   string `json:"signer,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
	LogIndex *int64 `json:"log_index,omitempty"`
	Reason   string `json:"reason,omitempty"` // set when Verified == false
}

// Options configures a single image verification request.
type Options struct {
	// Digest is the artifact's sha256 digest, hex-encoded, no "sha256:" prefix. Required.
	Digest string
	// Signer is the expected keyless identity (email or URI SAN), e.g.
	// "user@example.com" or
	// "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main".
	// Required for keyless verification; ignored when KeyPath is set.
	Signer string
	// Issuer is the expected OIDC issuer, e.g.
	// "https://token.actions.githubusercontent.com". Optional for keyless
	// verification (when empty, any issuer embedded in the certificate is
	// accepted as long as Signer matches).
	Issuer string
	// KeyPath, when set, switches to key-based verification against a
	// PEM-encoded public key instead of keyless/Fulcio identity verification.
	KeyPath string
	// BundlePath is the path to a Sigstore verification bundle (JSON).
	// Optional when Image is set.
	BundlePath string
	// Image is an OCI repository reference WITHOUT a tag or digest, e.g.
	// "ghcr.io/org/name". When set and BundlePath is empty, the signature is
	// resolved from the registry using cosign's <repo>:sha256-<digest>.sig
	// convention. A bare digest cannot identify a repository, which is why
	// this is needed rather than inferred.
	Image string
}

// Validate checks that Options is internally consistent, independent of any
// particular Verifier implementation.
func (o Options) Validate() error {
	if o.Digest == "" {
		return errors.New("cosignverify: Digest is required")
	}
	if o.KeyPath == "" && o.Signer == "" {
		return errors.New("cosignverify: Signer is required for keyless verification (or set KeyPath for key-based verification)")
	}
	return nil
}

// Verifier verifies a container image's cosign signature. Implementations
// must not panic. Operational failures (bad input, network/parse errors)
// that prevent verification from completing at all are returned as an error;
// a completed-but-failed verification (untrusted/missing signature) is
// reported via Verdict.Verified == false with Verdict.Reason set, and a nil
// error, so callers can always inspect the verdict and record it as evidence.
type Verifier interface {
	Verify(ctx context.Context, opts Options) (*Verdict, error)
}
