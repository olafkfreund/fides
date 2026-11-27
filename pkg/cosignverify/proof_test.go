package cosignverify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/root"
)

func proofValue[T any](t *testing.T, v T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func proofFile(t *testing.T, filename string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), filename)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyOfflinePinnedKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key = proofValue(t, key, err)
	const payloadType = "application/vnd.in-toto+json"
	statement := fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"image","digest":{"sha256":%q}}]}`, testDigest)
	digest := sha256.Sum256(fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(statement), statement))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	sig = proofValue(t, sig, err)
	makeProof := func(sig []byte) *Proof {
		b64 := base64.StdEncoding.EncodeToString
		return &Proof{Bundle: fmt.Appendf(nil, `{
			"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json",
			"verificationMaterial":{"publicKey":{"hint":"untrusted key hint"}},
			"dsseEnvelope":{"payloadType":%q,"payload":%q,"signatures":[{"sig":%q}]}
		}`, payloadType, b64([]byte(statement)), b64(sig))}
	}
	keyPath := func(key *ecdsa.PublicKey) string {
		der, err := x509.MarshalPKIXPublicKey(key)
		return proofFile(t, "key.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: proofValue(t, der, err)}))
	}
	opts := OfflineOptions{Digest: testDigest, KeyPath: keyPath(&key.PublicKey)}
	v := NewSigstoreVerifier()
	verdict, err := v.VerifyOffline(makeProof(sig), opts)
	if err != nil || !verdict.Verified || verdict.Method != "key" || verdict.LogIndex != nil {
		t.Fatalf("valid keyed proof: verdict=%+v error=%v", verdict, err)
	}

	conflictingTrust := opts
	conflictingTrust.Signer = "unverified@example.test"
	if _, err := v.VerifyOffline(makeProof(sig), conflictingTrust); err == nil {
		t.Fatal("offline verifier accepted both a pinned key and a keyless identity")
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey = proofValue(t, otherKey, err)
	altered := bytes.Clone(sig)
	altered[len(altered)-1] ^= 1
	for _, tc := range []struct {
		name  string
		opts  OfflineOptions
		proof *Proof
	}{
		{"wrong digest", OfflineOptions{Digest: otherDiges, KeyPath: opts.KeyPath}, makeProof(sig)},
		{"wrong key", OfflineOptions{Digest: testDigest, KeyPath: keyPath(&otherKey.PublicKey)}, makeProof(sig)},
		{"altered signature", opts, makeProof(altered)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := v.VerifyOffline(tc.proof, tc.opts)
			if err != nil || verdict.Verified {
				t.Fatalf("expected failed verification: verdict=%+v error=%v", verdict, err)
			}
		})
	}

	_, err = v.VerifyOffline(makeProof(sig), OfflineOptions{Digest: testDigest})
	if err == nil || !strings.Contains(err.Error(), "requires a trusted root") {
		t.Fatalf("expected missing trust error, got %v", err)
	}
	var historical Verdict
	if err := json.Unmarshal([]byte(`{"verified":true,"digest":"`+testDigest+`"}`), &historical); err != nil {
		t.Fatal(err)
	}
	_, err = v.VerifyOffline(historical.Proof, opts)
	if err == nil || !strings.Contains(err.Error(), "retained proof is missing") {
		t.Fatalf("expected missing proof error, got %v", err)
	}
}

func TestRetainAndVerifyOfflineKeylessProof(t *testing.T) {
	// The fixtures were signed by synthetic Fulcio, CT and Rekor keys.
	const signer, issuer = "signer@example.test", "https://issuer.example.test"
	rootPath := filepath.Join("testdata", "trusted_root.json")
	payload, err := os.ReadFile("testdata/registry_payload.json")
	payload = proofValue(t, payload, err)
	rawAnnotations, err := os.ReadFile("testdata/registry_annotations.json")
	var annotations map[string]string
	if err := json.Unmarshal(proofValue(t, rawAnnotations, err), &annotations); err != nil {
		t.Fatal(err)
	}
	layer, desc := layerFor(payload, annotations)
	image, err := mutate.Append(empty.Image, mutate.Addendum{Layer: layer, MediaType: desc.MediaType, Annotations: annotations})
	image = proofValue(t, image, err)
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	repo := strings.TrimPrefix(server.URL, "http://") + "/offline-fixture"
	tag, err := name.NewTag(signatureTag(repo, testDigest))
	if err := remote.Write(proofValue(t, tag, err), image); err != nil {
		t.Fatal(err)
	}

	verifier := NewSigstoreVerifier()
	verifyOpts := Options{Digest: testDigest, Signer: signer, Issuer: issuer, Image: repo}
	fetchLocalRoot := func() (*root.TrustedRoot, error) { return root.NewTrustedRootFromPath(rootPath) }
	v, err := verifier.verify(verifyOpts, fetchLocalRoot)
	if err != nil || !v.Verified || v.Proof == nil || v.Proof.Registry == nil {
		t.Fatalf("registry verification: verdict=%+v error=%v", v, err)
	}
	if p := v.Proof.Registry; !bytes.Equal(p.Payload, payload) || p.RekorBundle != annotations[annBundle] ||
		p.Signature != annotations[annSignature] || p.Certificate != annotations[annCertificate] {
		t.Fatal("retained registry proof differs from the original bytes")
	}
	server.Close()

	// Re-verify the evidence after its source registry has gone away.
	recorded, err := json.Marshal(v)
	var saved Verdict
	if err := json.Unmarshal(proofValue(t, recorded, err), &saved); err != nil {
		t.Fatal(err)
	}
	opts := OfflineOptions{Digest: testDigest, Signer: signer, Issuer: issuer, TrustedRootPath: rootPath}
	verdict, err := verifier.VerifyOffline(saved.Proof, opts)
	if err != nil || !verdict.Verified {
		t.Fatalf("retained registry proof: verdict=%+v error=%v", verdict, err)
	}
	wrongDigest := opts
	wrongDigest.Digest = otherDiges
	_, err = verifier.VerifyOffline(saved.Proof, wrongDigest)
	if err == nil || !strings.Contains(err.Error(), "is for digest") {
		t.Fatalf("expected image binding error, got %v", err)
	}

	// The modified payload still names the image.
	modified := *saved.Proof.Registry
	modified.Payload = bytes.TrimSpace(modified.Payload)
	wrongIssuer := opts
	wrongIssuer.Issuer = "https://other.example.test"
	wrongRoot := opts
	wrongRoot.TrustedRootPath = proofFile(t, "empty_trusted_root.json", []byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`))
	for _, tc := range []struct {
		name  string
		opts  OfflineOptions
		proof *Proof
	}{
		{"altered payload", opts, &Proof{Registry: &modified}},
		{"wrong issuer", wrongIssuer, saved.Proof},
		{"root without trusted keys", wrongRoot, saved.Proof},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := verifier.VerifyOffline(tc.proof, tc.opts)
			if err != nil || verdict.Verified {
				t.Fatalf("expected failed verification: verdict=%+v error=%v", verdict, err)
			}
		})
	}

	converted, err := buildFromLayer(layer, desc, testDigest)
	bundleJSON, err := proofValue(t, converted, err).Bundle.MarshalJSON()
	exactBundle := append(append([]byte(" \n"), proofValue(t, bundleJSON, err)...), '\n')
	sum := sha256.Sum256(payload)
	verifyOpts.Digest = hex.EncodeToString(sum[:])
	verifyOpts.BundlePath = proofFile(t, "bundle.json", exactBundle)
	v, err = verifier.verify(verifyOpts, fetchLocalRoot)
	if err != nil || !v.Verified || v.Proof == nil || !bytes.Equal(v.Proof.Bundle, exactBundle) {
		t.Fatalf("explicit bundle verification: verdict=%+v error=%v", v, err)
	}
	opts.Digest = verifyOpts.Digest
	verdict, err = verifier.VerifyOffline(v.Proof, opts)
	if err != nil || !verdict.Verified {
		t.Fatalf("retained bundle proof: verdict=%+v error=%v", verdict, err)
	}

	verifyOpts.Signer = "other@example.test"
	v, err = verifier.verify(verifyOpts, fetchLocalRoot)
	if err != nil || v.Verified || v.Proof != nil {
		t.Fatalf("a failed verdict should carry no proof: verdict=%+v error=%v", v, err)
	}
}
