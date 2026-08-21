package cosignverify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	prototlog "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// Cosign's signature layer annotations. Stable across cosign v1 and v2.
const (
	annSignature   = "dev.cosignproject.cosign/signature"
	annCertificate = "dev.sigstore.cosign/certificate"
	annBundle      = "dev.sigstore.cosign/bundle"

	// simplesigningMediaType is the layer cosign writes for a container image
	// signature. Anything else in the .sig manifest (attestations, SBOMs) is
	// not a signature and is skipped.
	simplesigningMediaType = "application/vnd.dev.cosign.simplesigning.v1+json"
)

// ErrNoSignatureInRegistry is returned when the signature tag does not exist
// or holds no cosign signature layer.
var ErrNoSignatureInRegistry = errors.New("cosignverify: no cosign signature found in the registry for this digest")

// simpleSigning is the payload cosign signs for a container image. The
// signature is over THESE BYTES, not over the image digest -- the image digest
// only appears inside. Binding the two is the caller's job; see
// discoverSignature.
type simpleSigning struct {
	Critical struct {
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
	} `json:"critical"`
}

// rekorBundle is cosign's legacy `dev.sigstore.cosign/bundle` annotation. It
// predates the Sigstore protobuf bundle and has no mediaType, so
// bundle.LoadJSONFromPath cannot read it -- hence the conversion below.
type rekorBundle struct {
	SignedEntryTimestamp string `json:"SignedEntryTimestamp"`
	Payload              struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
	} `json:"Payload"`
}

// signatureTag maps an image digest to the tag cosign stores its signature
// under: sha256:<hex> -> sha256-<hex>.sig
func signatureTag(repo, digest string) string {
	return fmt.Sprintf("%s:sha256-%s.sig", repo, strings.TrimPrefix(digest, "sha256:"))
}

// discoveredSignature is a cosign signature resolved from a registry, already
// bound to the requested image digest.
type discoveredSignature struct {
	// Bundle is the converted Sigstore bundle, ready for the same verifier the
	// --bundle path uses. No crypto is performed here: the conversion is
	// mechanical and sigstore-go remains the only thing that checks anything.
	Bundle *bundle.Bundle
	// PayloadDigest is sha256 of the simplesigning payload. This -- NOT the
	// image digest -- is what the signature covers, so it is what the
	// verification policy must assert.
	PayloadDigest []byte
}

// discoverSignature fetches <repo>:sha256-<digest>.sig and converts cosign's
// annotations into a Sigstore bundle.
//
// The security-critical step is the binding check. A cosign signature is made
// over the simplesigning payload, and that payload names the image it is for.
// Verifying the signature alone proves only "someone signed some payload" --
// without asserting that the payload names OUR digest, any valid signature for
// any image would satisfy any request. That check is unconditional here, and
// happens before anything is returned.
func discoverSignature(repo, digest string) (*discoveredSignature, error) {
	ref, err := name.ParseReference(signatureTag(repo, digest))
	if err != nil {
		return nil, fmt.Errorf("cosignverify: parse signature reference: %w", err)
	}
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrNoSignatureInRegistry, ref.String(), err)
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("cosignverify: read signature layers: %w", err)
	}
	manifest, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("cosignverify: read signature manifest: %w", err)
	}

	for i, desc := range manifest.Layers {
		if string(desc.MediaType) != simplesigningMediaType || i >= len(layers) {
			continue
		}
		sig, err := buildFromLayer(layers[i], desc, digest)
		if err != nil {
			// Keep looking: a .sig manifest can hold several signatures and
			// only one of them needs to be usable and for this image.
			continue
		}
		return sig, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrNoSignatureInRegistry, ref.String())
}

func buildFromLayer(layer v1.Layer, desc v1.Descriptor, wantDigest string) (*discoveredSignature, error) {
	rc, err := layer.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	payload, err := readAllLimited(rc)
	if err != nil {
		return nil, err
	}

	// --- Binding: this payload must name the image we were asked about.
	var ss simpleSigning
	if err := json.Unmarshal(payload, &ss); err != nil {
		return nil, fmt.Errorf("parse simplesigning payload: %w", err)
	}
	got := strings.TrimPrefix(ss.Critical.Image.DockerManifestDigest, "sha256:")
	want := strings.TrimPrefix(wantDigest, "sha256:")
	if got == "" || !strings.EqualFold(got, want) {
		return nil, fmt.Errorf("signature payload is for digest %q, not %q", got, want)
	}

	sigB64 := desc.Annotations[annSignature]
	certPEM := desc.Annotations[annCertificate]
	bundleJSON := desc.Annotations[annBundle]
	if sigB64 == "" || certPEM == "" || bundleJSON == "" {
		return nil, errors.New("signature layer is missing cosign annotations")
	}
	sigRaw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	var rb rekorBundle
	if err := json.Unmarshal([]byte(bundleJSON), &rb); err != nil {
		return nil, fmt.Errorf("parse rekor bundle annotation: %w", err)
	}
	body, err := base64.StdEncoding.DecodeString(rb.Payload.Body)
	if err != nil {
		return nil, fmt.Errorf("decode rekor body: %w", err)
	}
	set, err := base64.StdEncoding.DecodeString(rb.SignedEntryTimestamp)
	if err != nil {
		return nil, fmt.Errorf("decode signed entry timestamp: %w", err)
	}
	logID, err := hexOrRaw(rb.Payload.LogID)
	if err != nil {
		return nil, fmt.Errorf("decode log id: %w", err)
	}

	sum := sha256.Sum256(payload)

	pb := &protobundle.Bundle{
		// v0.1 deliberately. Cosign's legacy annotation carries only an
		// inclusion PROMISE (the SignedEntryTimestamp) and never a full
		// inclusion proof, and sigstore-go requires a proof from v0.2 onward.
		// Declaring a later version would make every converted bundle fail
		// validation for a field cosign does not publish.
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: pemToDER(certPEM)},
			},
			TlogEntries: []*prototlog.TransparencyLogEntry{{
				LogIndex:       rb.Payload.LogIndex,
				LogId:          &protocommon.LogId{KeyId: logID},
				KindVersion:    &prototlog.KindVersion{Kind: "hashedrekord", Version: "0.0.1"},
				IntegratedTime: rb.Payload.IntegratedTime,
				InclusionPromise: &prototlog.InclusionPromise{
					SignedEntryTimestamp: set,
				},
				CanonicalizedBody: body,
			}},
		},
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    sum[:],
				},
				Signature: sigRaw,
			},
		},
	}

	b, err := bundle.NewBundle(pb)
	if err != nil {
		return nil, fmt.Errorf("build sigstore bundle: %w", err)
	}
	return &discoveredSignature{Bundle: b, PayloadDigest: sum[:]}, nil
}

// maxPayloadBytes caps the simplesigning blob. It is a small JSON document;
// anything larger is not one, and reading it unbounded would let a registry
// response size be chosen by whoever controls the registry.
const maxPayloadBytes = 1 << 20 // 1 MiB

func readAllLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxPayloadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxPayloadBytes {
		return nil, fmt.Errorf("cosignverify: signature payload exceeds %d bytes", maxPayloadBytes)
	}
	return b, nil
}

// pemToDER returns the DER bytes of the first certificate in a PEM blob, or
// nil when it does not parse. A nil here fails bundle construction rather than
// verifying anything, which is the safe direction.
func pemToDER(pemStr string) []byte {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil
	}
	return block.Bytes
}

// hexOrRaw decodes Rekor's logID, which is hex-encoded in the legacy bundle.
func hexOrRaw(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty log id")
	}
	return hex.DecodeString(s)
}
