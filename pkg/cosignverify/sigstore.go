package cosignverify

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
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
	return s.verify(opts, root.FetchTrustedRoot)
}

func (s *SigstoreVerifier) verify(opts Options, fetchRoot func() (*root.TrustedRoot, error)) (*Verdict, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if opts.BundlePath == "" && opts.Image == "" {
		return nil, ErrBundleRequired
	}

	digestBytes, err := hex.DecodeString(opts.Digest)
	if err != nil {
		return nil, fmt.Errorf("cosignverify: invalid --sha256 digest %q: %w", opts.Digest, err)
	}

	// artifactDigest is what the signature is asserted to cover.
	//
	// For an explicit --bundle that is the image digest itself. For a cosign
	// signature discovered in a registry it is NOT: cosign signs a
	// simplesigning payload which merely NAMES the image, so the policy must
	// assert sha256(payload). The link back to the image digest is the binding
	// check inside discoverSignature, which refuses any payload naming a
	// different image -- without it, a valid signature for any image would
	// satisfy a request about any other.
	artifactDigest := digestBytes

	var b *bundle.Bundle
	proof := &Proof{}
	if opts.BundlePath != "" {
		proof.Bundle, err = os.ReadFile(opts.BundlePath) // #nosec G304 -- caller-supplied local bundle path.
		if err == nil {
			b = new(bundle.Bundle)
			err = b.UnmarshalJSON(proof.Bundle)
		}
		if err != nil {
			return nil, fmt.Errorf("cosignverify: load bundle %q: %w", opts.BundlePath, err)
		}
	} else {
		found, derr := discoverSignature(opts.Image, opts.Digest)
		if derr != nil {
			return nil, derr
		}
		b = found.Bundle
		artifactDigest = found.PayloadDigest
		proof.Registry = found.Proof
	}

	var trustedRoot *root.TrustedRoot
	if opts.KeyPath == "" {
		trustedRoot, err = fetchRoot()
		if err != nil {
			return nil, fmt.Errorf("cosignverify: fetch trusted root: %w", err)
		}
	}
	verdict, err := verifyBundle(opts, b, artifactDigest, trustedRoot, false)
	if err == nil && verdict.Verified {
		verdict.Proof = proof
	}
	return verdict, err
}

// VerifyOffline verifies a retained proof against the caller's expected digest
// and local trust. It requires no registry, Rekor, or TUF access. Invalid
// inputs return an error, and failed signature checks return a failed verdict.
func (s *SigstoreVerifier) VerifyOffline(proof *Proof, opts OfflineOptions) (*Verdict, error) {
	if proof == nil || (len(proof.Bundle) == 0 && proof.Registry == nil) {
		return nil, errors.New("cosignverify: retained proof is missing")
	}
	if len(proof.Bundle) != 0 && proof.Registry != nil {
		return nil, errors.New("cosignverify: retained proof has multiple sources")
	}
	digest, err := hex.DecodeString(opts.Digest)
	if err != nil || len(digest) != sha256.Size {
		return nil, errors.New("cosignverify: expected a SHA-256 digest in hex")
	}
	opts.Digest = hex.EncodeToString(digest)
	if opts.KeyPath != "" && (opts.TrustedRootPath != "" || opts.Signer != "" || opts.Issuer != "") {
		return nil, errors.New("cosignverify: choose either a pinned key or a trusted root, signer, and issuer")
	}

	var b *bundle.Bundle
	if proof.Registry == nil {
		b = new(bundle.Bundle)
		if err := b.UnmarshalJSON(proof.Bundle); err != nil {
			return nil, fmt.Errorf("cosignverify: load retained bundle: %w", err)
		}
	} else {
		if len(proof.Registry.Payload) > maxPayloadBytes {
			return nil, fmt.Errorf("cosignverify: signature payload exceeds %d bytes", maxPayloadBytes)
		}
		found, err := proof.Registry.bind(opts.Digest)
		if err != nil {
			return nil, fmt.Errorf("cosignverify: bind retained registry proof: %w", err)
		}
		b = found.Bundle
		digest = found.PayloadDigest
	}

	var trustedRoot *root.TrustedRoot
	if opts.KeyPath == "" {
		if opts.TrustedRootPath == "" || opts.Signer == "" || opts.Issuer == "" {
			return nil, errors.New("cosignverify: offline keyless verification requires a trusted root, signer, and issuer")
		}
		trustedRoot, err = root.NewTrustedRootFromPath(opts.TrustedRootPath)
		if err != nil {
			return nil, fmt.Errorf("cosignverify: load trusted root: %w", err)
		}
	}

	return verifyBundle(Options{
		Digest: opts.Digest, KeyPath: opts.KeyPath, Signer: opts.Signer, Issuer: opts.Issuer,
	}, b, digest, trustedRoot, opts.KeyPath != "")
}

func verifyBundle(opts Options, b *bundle.Bundle, artifactDigest []byte, trustedRoot *root.TrustedRoot, pinnedKeyOnly bool) (*Verdict, error) {
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
		trustedMaterial = trustedRoot
		identity, err := verify.NewShortCertificateIdentity(opts.Issuer, "", opts.Signer, "")
		if err != nil {
			return nil, fmt.Errorf("cosignverify: build certificate identity policy: %w", err)
		}
		policyOpt = verify.WithCertificateIdentity(identity)
	}

	verifierOpts := []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	}
	if pinnedKeyOnly {
		// The pinned key authenticates the signature without a log or a timestamp.
		verifierOpts = []verify.VerifierOption{verify.WithNoObserverTimestamps()}
	}
	sev, err := verify.NewVerifier(trustedMaterial, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("cosignverify: build verifier: %w", err)
	}

	result, err := sev.Verify(b, verify.NewPolicy(verify.WithArtifactDigest("sha256", artifactDigest), policyOpt))
	//nolint:nilerr // A failed verification is a verdict, not an operational
	// error: verdict.Verified stays false and the reason is attached, so the
	// caller records it as evidence and still gates on it
	// (cmd/cli/verify_image.go:93 exits non-zero on !verdict.Verified).
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
	if !pinnedKeyOnly {
		if entries, terr := b.TlogEntries(); terr == nil && len(entries) > 0 {
			li := entries[0].LogIndex()
			verdict.LogIndex = &li
		}
	}

	return verdict, nil
}
