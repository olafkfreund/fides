package cosignverify

import (
	"context"
	"crypto"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

// SigstoreVerifier verifies a pre-fetched Sigstore bundle (Options.BundlePath)
// using github.com/sigstore/sigstore-go:
//
//   - keyless: validates the Fulcio certificate chain and SCT, the Rekor
//     transparency-log inclusion proof, and the certificate's SAN/issuer
//     against Options.Signer/Options.Issuer — anchored in the public-good
//     Sigstore trusted root (fetched live via TUF).
//   - key-based (Options.KeyPath set): validates the bundle's signature
//     against the PEM-encoded public key.
//
// In both cases the artifact digest embedded in the bundle's signed content
// is checked against Options.Digest, so a bundle for a different image
// cannot be replayed against this digest.
type SigstoreVerifier struct{}

// NewSigstoreVerifier returns a Verifier backed by github.com/sigstore/sigstore-go.
func NewSigstoreVerifier() *SigstoreVerifier {
	return &SigstoreVerifier{}
}

// Verify implements Verifier.
func (s *SigstoreVerifier) Verify(_ context.Context, opts Options) (*Verdict, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if opts.BundlePath == "" {
		return nil, ErrBundleRequired
	}

	digestBytes, err := hex.DecodeString(opts.Digest)
	if err != nil {
		return nil, fmt.Errorf("cosignverify: invalid --sha256 digest %q: %w", opts.Digest, err)
	}

	b, err := bundle.LoadJSONFromPath(opts.BundlePath)
	if err != nil {
		return nil, fmt.Errorf("cosignverify: load bundle %q: %w", opts.BundlePath, err)
	}

	verdict := &Verdict{Digest: opts.Digest}

	var trustedMaterial root.TrustedMaterial
	var policyOpt verify.PolicyOption

	if opts.KeyPath != "" {
		verdict.Method = "key"
		keyVerifier, err := signature.LoadVerifierFromPEMFile(opts.KeyPath, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("cosignverify: load public key %q: %w", opts.KeyPath, err)
		}
		trustedMaterial = root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
			return root.NewExpiringKey(keyVerifier, time.Time{}, time.Time{}), nil
		})
		policyOpt = verify.WithKey()
	} else {
		verdict.Method = "keyless"
		trustedRoot, err := root.FetchTrustedRoot()
		if err != nil {
			return nil, fmt.Errorf("cosignverify: fetch trusted root: %w", err)
		}
		trustedMaterial = trustedRoot
		identity, err := verify.NewShortCertificateIdentity(opts.Issuer, "", opts.Signer, "")
		if err != nil {
			return nil, fmt.Errorf("cosignverify: build certificate identity policy: %w", err)
		}
		policyOpt = verify.WithCertificateIdentity(identity)
	}

	sev, err := verify.NewSignedEntityVerifier(trustedMaterial,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("cosignverify: build verifier: %w", err)
	}

	result, err := sev.Verify(b, verify.NewPolicy(verify.WithArtifactDigest("sha256", digestBytes), policyOpt))
	if err != nil {
		// A completed-but-failed verification is not an operational error:
		// report it on the verdict so the caller can still record it as
		// evidence and gate the deploy on Verdict.Verified.
		verdict.Reason = err.Error()
		return verdict, nil
	}

	verdict.Verified = true
	if result.Signature != nil && result.Signature.Certificate != nil {
		verdict.Signer = result.Signature.Certificate.SubjectAlternativeName
		verdict.Issuer = result.Signature.Certificate.Issuer
	}
	if verdict.Signer == "" {
		verdict.Signer = opts.Signer
	}
	if verdict.Issuer == "" {
		verdict.Issuer = opts.Issuer
	}
	if entries, terr := b.TlogEntries(); terr == nil && len(entries) > 0 {
		li := entries[0].LogIndex()
		verdict.LogIndex = &li
	}

	return verdict, nil
}
