package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"fides/pkg/auditpack"
	"fides/pkg/cosignverify"
	"fides/pkg/ledger"

	"github.com/digitorus/timestamp"
)

func auditValue[T any](t *testing.T, value T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func auditFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func auditJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	return auditValue(t, raw, err)
}

func auditDigest(raw []byte) string {
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:])
}

func archiveKeyFixture(t *testing.T, dir, filename string) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	p := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: auditValue(t, der, err)})
	return key, auditFile(t, dir, filename, p)
}

func timestampFixture(t *testing.T, dir string) (string, func(string) []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key = auditValue(t, key, err)
	now := time.Now().UTC()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Audit fixture TSA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	der = auditValue(t, der, err)
	cert, err = x509.ParseCertificate(der)
	cert = auditValue(t, cert, err)
	roots := auditFile(t, dir, "tsa.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return roots, func(head string) []byte {
		t.Helper()
		imprint := sha256.Sum256([]byte(head))
		token := timestamp.Timestamp{
			HashAlgorithm: crypto.SHA256, HashedMessage: imprint[:], Time: now,
			Policy: asn1.ObjectIdentifier{1, 2, 3, 4, 1}, AddTSACertificate: true,
		}
		raw, err := token.CreateResponseWithOpts(cert, key, crypto.SHA256)
		return auditValue(t, raw, err)
	}
}

func signerFixtures(t *testing.T, dir string) (provider, cosign, policyPath string) {
	t.Helper()
	providerDigest := auditDigest([]byte("provider artifact"))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key = auditValue(t, key, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	auditFile(t, dir, "provider.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: auditValue(t, der, err)}))
	const payloadType = "application/vnd.in-toto+json"
	statement := fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"fixture","digest":{"sha256":%q}}]}`, providerDigest)
	pae := sha256.Sum256(fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(statement), statement))
	sig, err := ecdsa.SignASN1(rand.Reader, key, pae[:])
	b64 := base64.StdEncoding.EncodeToString
	bundle := fmt.Appendf(nil, `{
		"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial":{"publicKey":{"hint":"fixture"}},
		"dsseEnvelope":{"payloadType":%q,"payload":%q,"signatures":[{"sig":%q}]}
	}`, payloadType, b64([]byte(statement)), b64(auditValue(t, sig, err)))
	provider = fmt.Sprintf(`{"provider":"github","signer_proof":{"version":1,"format":"sigstore-dsse-bundle","artifact_sha256":%q,"bundle_base64":%q}}`, providerDigest, b64(bundle))

	const cosignDigest = "c127b69288d60290be9a2da7fc220d8dd161921aa4b18dff75c98a1cc14a229a"
	readFixture := func(name string) []byte {
		content, err := os.ReadFile(filepath.Join("..", "..", "pkg", "cosignverify", "testdata", name))
		return auditValue(t, content, err)
	}
	auditFile(t, dir, "sigstore.json", readFixture("trusted_root.json"))
	var annotations map[string]string
	if err := json.Unmarshal(readFixture("registry_annotations.json"), &annotations); err != nil {
		t.Fatal(err)
	}
	cosign = string(auditJSON(t, cosignverify.Verdict{
		Verified: true, Digest: cosignDigest, Method: "keyless",
		Proof: &cosignverify.Proof{Registry: &cosignverify.RegistryProof{
			Payload: readFixture("registry_payload.json"), Signature: annotations["dev.cosignproject.cosign/signature"],
			Certificate: annotations["dev.sigstore.cosign/certificate"], RekorBundle: annotations["dev.sigstore.cosign/bundle"],
		}},
	}))
	policyPath = auditFile(t, dir, "policy.json", auditJSON(t, map[string]any{
		providerDigest: map[string]string{"key": "provider.pem"},
		cosignDigest: map[string]string{
			"trusted_root": "sigstore.json", "signer": "signer@example.test", "issuer": "https://issuer.example.test",
		},
	}))
	return provider, cosign, policyPath
}

const fixtureTrail = "308aa429-6598-4d3b-92a8-11e640eb2e61"

func makeAuditFixture(t *testing.T, key ed25519.PrivateKey, provider, cosign string, token func(string) []byte, modify func(*auditpack.Manifest, *[]auditpack.Anchor)) ([]byte, []byte) {
	t.Helper()
	content := "attachment with exact bytes\x00\n"
	attachment := auditpack.Attachment{
		ID: "attachment-1", AttestationID: "record-1", Name: "audit.txt", SHA256: auditDigest([]byte(content)),
		Size: int64(len(content)), Member: "attachments/attachment-1",
	}
	providerArtifact := auditDigest([]byte("provider artifact"))
	const cosignArtifact = "c127b69288d60290be9a2da7fc220d8dd161921aa4b18dff75c98a1cc14a229a"
	entries := []ledger.Entry{
		{TrailID: fixtureTrail, Name: "provider evidence", TypeName: "slsa-provenance", Payload: provider, Version: 2, IsCompliant: true},
		{TrailID: fixtureTrail, Name: "cosign evidence", TypeName: "cosign-verification", Payload: cosign, Version: 2, IsCompliant: true},
	}
	inputs := func(artifact string, attachments string) string {
		return ledger.CanonicalJSONV2(fmt.Sprintf(`{"artifact_sha256":%q,"attachments":%s,"policy":null,"signed_by":null,"signature":null,"signature_algorithm":null,"manifestation_reason":null}`, artifact, attachments))
	}
	entries[0].Evidence = inputs(providerArtifact, fmt.Sprintf(`[{"id":%q,"name":%q,"size":%d,"sha256":%q}]`, attachment.ID, attachment.Name, attachment.Size, attachment.SHA256))
	entries[1].Evidence = inputs(cosignArtifact, "[]")
	var records []auditpack.ChainRecord
	head := ""
	for i, entry := range entries {
		entry.PrevHash = head
		entry.ContentHash = ledger.ContentHashV2(entry.TrailID, entry.Name, entry.TypeName, entry.Payload, entry.IsCompliant, entry.PrevHash, entry.Evidence)
		entries[i] = entry
		records = append(records, auditpack.ChainRecord{ID: fmt.Sprintf("record-%d", i+1), Entry: entry})
		head = entry.ContentHash
	}
	manifest := auditpack.Manifest{Version: 1, TrailID: fixtureTrail, ChainHead: head, Coverage: ledger.Verify(entries), Attachments: []auditpack.Attachment{attachment}}
	anchors := []auditpack.Anchor{{Head: head, Token: token(head)}}
	if modify != nil {
		modify(&manifest, &anchors)
	}
	var archive bytes.Buffer
	w := auditpack.NewWriter(&archive)
	for _, member := range []struct {
		name string
		data []byte
	}{
		{"trail.json", auditJSON(t, map[string]string{"id": fixtureTrail})},
		{"chain.json", auditJSON(t, records)},
		{"anchors.json", auditJSON(t, anchors)},
		{"approvals.json", []byte("[]")},
		{"artifacts.json", auditJSON(t, []map[string]string{{"sha256": providerArtifact}, {"sha256": cosignArtifact}})},
		{attachment.Member, []byte(content)},
	} {
		if _, err := w.Add(member.name, bytes.NewReader(member.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(manifest); err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(archive.Bytes())
	sig, err := auditpack.Sign(key, d[:])
	return archive.Bytes(), auditValue(t, sig, err)
}

func TestVerifyPackLocalFixtures(t *testing.T) {
	dir := t.TempDir()
	key, pub := archiveKeyFixture(t, dir, "archive.pem")
	_, previousPub := archiveKeyFixture(t, dir, "previous.pem")
	roots, token := timestampFixture(t, dir)
	_, badRoots := archiveKeyFixture(t, dir, "not-a-root.pem")
	provider, cosign, policy := signerFixtures(t, dir)
	run := func(t *testing.T, zip, sig []byte, options []string, want int, message string) {
		t.Helper()
		dir := t.TempDir()
		path := auditFile(t, dir, "pack.zip", zip)
		auditFile(t, dir, "pack.zip.sig", sig)
		var out bytes.Buffer
		if code := runVerifyPack(&out, append([]string{path}, options...)); code != want || !strings.Contains(out.String(), message) {
			t.Fatalf("got exit %d, expected %d and %q in %s", code, want, message, out.String())
		}
	}
	opts := []string{"--archive-key", previousPub, "--archive-key", pub, "--tsa-roots", roots, "--signer-policy", policy}
	valid, validSig := makeAuditFixture(t, key, provider, cosign, token, nil)
	run(t, valid, validSig, opts, 0, "Verified audit pack")
	run(t, valid, validSig, []string{"--archive-key", previousPub}, 2, "untrusted archive signing key")
	run(t, valid, validSig, []string{"--archive-key", pub}, 2, "no local signer policy")
	run(t, valid, validSig, []string{"--archive-key", pub, "--signer-policy", policy}, 2, "local TSA roots")
	run(t, valid, validSig, []string{"--archive-key", pub, "--tsa-roots", badRoots}, 1, "no certificates")
	changed := bytes.Clone(valid)
	changed[len(changed)-1] ^= 1
	run(t, changed, validSig, opts, 2, "signature does not match")

	historical := `{"provider":"github"}`
	zip, sig := makeAuditFixture(t, key, historical, cosign, token, nil)
	run(t, zip, sig, opts, 3, "missing signer proof")
	zip, sig = makeAuditFixture(t, key, historical, strings.Replace(cosign, "registry", "malformed", 1), token, nil)
	run(t, zip, sig, opts, 2, "signer proof")
	zip, sig = makeAuditFixture(t, key, historical, cosign, token, func(_ *auditpack.Manifest, anchors *[]auditpack.Anchor) {
		(*anchors)[0].Token = token("different head")
	})
	run(t, zip, sig, opts, 2, "timestamp does not bind")
	zip, sig = makeAuditFixture(t, key, provider, cosign, token, func(m *auditpack.Manifest, _ *[]auditpack.Anchor) {
		m.Attachments[0].Name = "substituted.txt"
	})
	run(t, zip, sig, opts, 2, "does not match its v2 commitment")
}

func TestDownloadSignedAuditPublishesPair(t *testing.T) {
	raw := []byte("fixture download body")
	key, _ := archiveKeyFixture(t, t.TempDir(), "archive.pem")
	digest := sha256.Sum256(raw)
	sig, err := auditpack.Sign(key, digest[:])
	sig = auditValue(t, sig, err)
	for _, tc := range []string{"success", "existing ZIP", "signature symlink", "missing header", "truncated"} {
		t.Run(tc, func(t *testing.T) {
			dir := t.TempDir()
			dest := filepath.Join(dir, "pack.zip")
			if tc == "existing ZIP" {
				auditFile(t, dir, "pack.zip", []byte("existing file"))
			}
			if tc == "signature symlink" {
				if err := os.Symlink("pack.zip", dest+".sig"); err != nil {
					t.Fatal(err)
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/trails/"+fixtureTrail+"/signed-audit-pack" || r.Header.Get("Authorization") != "Bearer fixture" {
					t.Errorf("unexpected download request %s", r.URL.Path)
				}
				if tc != "missing header" {
					w.Header().Set(auditpack.SignatureHeader, base64.StdEncoding.EncodeToString(sig))
				}
				if tc == "truncated" {
					w.Header().Set("Content-Length", strconv.Itoa(len(raw)+10))
				}
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			err := downloadSignedAudit(CLIConfig{ServerURL: server.URL, Token: "fixture"}, fixtureTrail, dest)
			if (err == nil) != (tc == "success") {
				t.Fatalf("download error = %v", err)
			}
			files, err := os.ReadDir(dir)
			files = auditValue(t, files, err)
			switch tc {
			case "success":
				for path, want := range map[string][]byte{dest: raw, dest + ".sig": sig} {
					got, err := os.ReadFile(path)
					if !bytes.Equal(auditValue(t, got, err), want) {
						t.Fatalf("wrong bytes in %s", path)
					}
				}
				if len(files) != 2 {
					t.Fatalf("unexpected files: %v", files)
				}
			case "existing ZIP":
				got, err := os.ReadFile(dest)
				if len(files) != 1 || string(auditValue(t, got, err)) != "existing file" {
					t.Fatalf("existing ZIP changed or signature left behind: %v", files)
				}
			case "signature symlink":
				if len(files) != 1 || files[0].Type()&os.ModeSymlink == 0 {
					t.Fatalf("signature symlink changed or ZIP left behind: %v", files)
				}
			default:
				if len(files) != 0 {
					t.Fatalf("partial download left files: %v", files)
				}
			}
		})
	}
}
