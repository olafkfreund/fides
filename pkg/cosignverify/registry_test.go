package cosignverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	testDigest = "c127b69288d60290be9a2da7fc220d8dd161921aa4b18dff75c98a1cc14a229a"
	otherDiges = "5c0c7c4205737e7eb0bb80045e5ba5271487c755b19b3a3d33587a13fc58a62b"
)

func TestSignatureTag(t *testing.T) {
	want := "ghcr.io/org/app:sha256-" + testDigest + ".sig"
	for _, in := range []string{testDigest, "sha256:" + testDigest} {
		if got := signatureTag("ghcr.io/org/app", in); got != want {
			t.Errorf("signatureTag(%q) = %q, want %q", in, got, want)
		}
	}
}

// payloadFor builds a simplesigning payload naming the given image digest.
func payloadFor(digest string) []byte {
	b, _ := json.Marshal(map[string]any{
		"critical": map[string]any{
			"image": map[string]any{"docker-manifest-digest": "sha256:" + digest},
		},
	})
	return b
}

func layerFor(payload []byte, ann map[string]string) (v1.Layer, v1.Descriptor) {
	l := static.NewLayer(payload, types.MediaType(simplesigningMediaType))
	d, _ := l.Digest()
	sz, _ := l.Size()
	return l, v1.Descriptor{
		MediaType:   types.MediaType(simplesigningMediaType),
		Digest:      d,
		Size:        sz,
		Annotations: ann,
	}
}

func goodAnnotations() map[string]string {
	rb, _ := json.Marshal(rekorBundle{
		SignedEntryTimestamp: base64.StdEncoding.EncodeToString([]byte("set")),
		Payload: struct {
			Body           string `json:"body"`
			IntegratedTime int64  `json:"integratedTime"`
			LogIndex       int64  `json:"logIndex"`
			LogID          string `json:"logID"`
		}{
			// A structurally real hashedrekord entry. sigstore-go parses
			// CanonicalizedBody during bundle validation and rejects anything
			// that is not a recognisable Rekor type — including a public key
			// that is not real PEM — so a stub body will not do.
			Body:           base64.StdEncoding.EncodeToString(hashedRekordBody()),
			IntegratedTime: 1786653016,
			LogIndex:       2455904195,
			LogID:          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
		},
	})
	return map[string]string{
		annSignature:   base64.StdEncoding.EncodeToString([]byte("signature-bytes")),
		annCertificate: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		annBundle:      string(rb),
	}
}

// TestBuildFromLayerRejectsWrongDigest is the important one.
//
// cosign signs a simplesigning payload that NAMES an image; the signature is
// not over the image digest itself. So a signature that verifies perfectly is
// still only evidence about whatever image its payload names. Without this
// binding check, a valid signature for image A would satisfy a request about
// image B — the whole verification would be sound and completely meaningless.
func TestBuildFromLayerRejectsWrongDigest(t *testing.T) {
	layer, desc := layerFor(payloadFor(otherDiges), goodAnnotations())
	_, err := buildFromLayer(layer, desc, testDigest)
	if err == nil {
		t.Fatal("accepted a signature whose payload names a DIFFERENT image digest")
	}
	if !strings.Contains(err.Error(), "is for digest") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// A payload with no digest at all must not be treated as a match either — an
// empty string must never compare equal to the requested digest.
func TestBuildFromLayerRejectsEmptyDigest(t *testing.T) {
	layer, desc := layerFor([]byte(`{"critical":{"image":{}}}`), goodAnnotations())
	if _, err := buildFromLayer(layer, desc, testDigest); err == nil {
		t.Fatal("accepted a payload that names no image digest")
	}
}

func TestBuildFromLayerRejectsTamperedPayload(t *testing.T) {
	layer, desc := layerFor([]byte("not json at all"), goodAnnotations())
	if _, err := buildFromLayer(layer, desc, testDigest); err == nil {
		t.Fatal("accepted an unparseable simplesigning payload")
	}
}

func TestBuildFromLayerRequiresAllAnnotations(t *testing.T) {
	for _, missing := range []string{annSignature, annCertificate, annBundle} {
		ann := goodAnnotations()
		delete(ann, missing)
		layer, desc := layerFor(payloadFor(testDigest), ann)
		if _, err := buildFromLayer(layer, desc, testDigest); err == nil {
			t.Errorf("accepted a signature layer with %s missing", missing)
		}
	}
}

func TestBuildFromLayerRejectsUndecodableAnnotations(t *testing.T) {
	cases := map[string]string{
		annSignature: "!!! not base64 !!!",
		annBundle:    "{not json",
	}
	for k, v := range cases {
		ann := goodAnnotations()
		ann[k] = v
		layer, desc := layerFor(payloadFor(testDigest), ann)
		if _, err := buildFromLayer(layer, desc, testDigest); err == nil {
			t.Errorf("accepted an undecodable %s", k)
		}
	}
}

// The happy path builds a bundle and reports the digest of the PAYLOAD, which
// is what the verification policy must assert — not the image digest.
func TestBuildFromLayerHappyPathBindsPayloadDigest(t *testing.T) {
	payload := payloadFor(testDigest)
	layer, desc := layerFor(payload, goodAnnotations())
	got, err := buildFromLayer(layer, desc, testDigest)
	if err != nil {
		t.Fatalf("buildFromLayer: %v", err)
	}
	if got.Bundle == nil {
		t.Fatal("no bundle built")
	}
	if len(got.PayloadDigest) != 32 {
		t.Fatalf("PayloadDigest is %d bytes, want 32", len(got.PayloadDigest))
	}
	// It must be sha256(payload), NOT the image digest.
	if strings.EqualFold(hexOf(got.PayloadDigest), testDigest) {
		t.Fatal("PayloadDigest equals the image digest; the policy would assert the wrong artifact")
	}
}

// Verify must still refuse when it has neither a bundle nor an image to
// resolve one from, rather than silently verifying nothing.
func TestVerifyRequiresBundleOrImage(t *testing.T) {
	_, err := NewSigstoreVerifier().Verify(t.Context(), Options{
		Digest: testDigest,
		Signer: "someone@example.com",
	})
	if !errors.Is(err, ErrBundleRequired) {
		t.Fatalf("err = %v, want ErrBundleRequired", err)
	}
}

func hexOf(b []byte) string {
	const hextable = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hextable[v>>4]
		out[i*2+1] = hextable[v&0x0f]
	}
	return string(out)
}

// hashedRekordBody returns a structurally valid Rekor hashedrekord entry, with
// a genuinely PEM-encoded public key. sigstore-go validates this during bundle
// construction; hand-waved fixtures are rejected.
func hashedRekordBody() []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	body, _ := json.Marshal(map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "hashedrekord",
		"spec": map[string]any{
			"data": map[string]any{
				"hash": map[string]any{"algorithm": "sha256", "value": testDigest},
			},
			"signature": map[string]any{
				// A REAL signature over the hashed artifact, IEEE P1363
				// encoded (r||s, fixed width). sigstore-go verifies this while
				// building the bundle — which is exactly the property that
				// stops the conversion in registry.go from ever producing a
				// bundle that only looks well-formed.
				"content":   base64.StdEncoding.EncodeToString(p1363Sign(key, mustHex(testDigest))),
				"publicKey": map[string]any{"content": base64.StdEncoding.EncodeToString(pubPEM)},
			},
		},
	})
	return body
}

// p1363Sign signs digest with key and returns the IEEE P1363 (r||s) encoding
// that Sigstore expects, rather than Go's default ASN.1 DER.
func p1363Sign(key *ecdsa.PrivateKey, digest []byte) []byte {
	r, sv, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		panic(err)
	}
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*byteLen)
	r.FillBytes(out[:byteLen])
	sv.FillBytes(out[byteLen:])
	return out
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
