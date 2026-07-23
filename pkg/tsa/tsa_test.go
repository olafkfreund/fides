package tsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

// mintToken builds a valid RFC3161 timestamp response over headHex using a
// throwaway self-signed TSA certificate — no live network needed.
func mintToken(t *testing.T, headHex string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test TSA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	digest := sha256.Sum256([]byte(headHex))
	ts := &timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     digest[:],
		Time:              time.Now(),
		SerialNumber:      big.NewInt(42),
		Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1}, // required TSTInfo policy OID
		Certificates:      []*x509.Certificate{cert},
		AddTSACertificate: true,
	}
	resp, err := ts.CreateResponse(cert, key)
	if err != nil {
		t.Fatalf("create response: %v", err)
	}
	return resp
}

func TestVerifyToken(t *testing.T) {
	const head = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	token := mintToken(t, head)

	// Valid: the token verifies against the head it was minted over.
	got, err := VerifyToken(token, head)
	if err != nil {
		t.Fatalf("VerifyToken valid case: %v", err)
	}
	if got.IsZero() {
		t.Fatal("expected a non-zero timestamp")
	}

	// Tamper: a chain whose head changed no longer matches the anchor.
	if _, err := VerifyToken(token, "deadbeef"); err == nil {
		t.Fatal("expected verification to FAIL for a tampered/mismatched head")
	}

	// Garbage token must not parse.
	if _, err := VerifyToken([]byte("not a timestamp response"), head); err == nil {
		t.Fatal("expected parse failure for a garbage token")
	}
}
