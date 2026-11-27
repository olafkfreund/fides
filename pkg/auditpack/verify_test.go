package auditpack

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"fides/pkg/cosignverify"
	"fides/pkg/ledger"
)

func TestRetainedProofMustMatchLegacyArtifactLink(t *testing.T) {
	recorded := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	proof, err := json.Marshal(map[string]any{
		"digest": other, "proof": cosignverify.Proof{Bundle: []byte(`{}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	record := ChainRecord{Entry: ledger.Entry{Version: 1, TypeName: "cosign-verification", Payload: string(proof)}}
	if _, err := verifySignerProof(record, &recorded, false, nil, nil); err == nil || !strings.Contains(err.Error(), "recorded artifact") {
		t.Fatalf("expected a different linked artifact to fail proof verification, got %v", err)
	}
}

func TestArchiveMembership(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := Trust{ArchiveKeys: []ed25519.PublicKey{pub}}
	check := func(t *testing.T, raw []byte, message string) {
		t.Helper()
		digest := sha256.Sum256(raw)
		signature, err := Sign(key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(bytes.NewReader(raw), signature, trust); err == nil || !strings.Contains(err.Error(), message) {
			t.Fatalf("expected archive rejection containing %q, got %v", message, err)
		}
	}

	digest := sha256.Sum256([]byte("trail"))
	member := Member{Name: "trail.json", Size: 5, SHA256: hex.EncodeToString(digest[:])}
	base := []string{member.Name}
	cases := []struct {
		name, message string
		names         []string
		members       []Member
	}{
		{"duplicate ZIP member", "duplicate ZIP member", append(slices.Clone(base), base...), []Member{member}},
		{"duplicate manifest member", "duplicate manifest member", base, []Member{member, member}},
		{"unlisted member", "different member counts", append(slices.Clone(base), "extra.txt"), []Member{member}},
		{"missing member", "missing ZIP member", []string{"wrong.txt"}, []Member{member}},
		{"noncanonical name", "invalid ZIP member", []string{"x/../trail.json"}, []Member{member}},
		{"digest mismatch", "SHA-256 mismatch", base, []Member{{Name: member.Name, Size: member.Size, SHA256: strings.Repeat("a", 64)}}},
		{"size mismatch", "size mismatch", base, []Member{{Name: member.Name, Size: 4, SHA256: member.SHA256}}},
	}
	makeZIP := func(t *testing.T, names []string, members []Member) []byte {
		t.Helper()
		var raw bytes.Buffer
		w := zip.NewWriter(&raw)
		for _, name := range names {
			f, err := w.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(f, "trail"); err != nil {
				t.Fatal(err)
			}
		}
		f, err := w.Create(manifestName)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(f).Encode(Manifest{Version: Version, TrailID: "trail", Members: members}); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return raw.Bytes()
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { check(t, makeZIP(t, tc.names, tc.members), tc.message) })
	}
	t.Run("local header alias", func(t *testing.T) {
		raw := makeZIP(t, base, []Member{member})
		raw[30] = 'x' // First byte of the name in the local ZIP header.
		check(t, raw, "local member does not match")
	})
	t.Run("signature before ZIP", func(t *testing.T) {
		raw := []byte("not a ZIP")
		digest := sha256.Sum256([]byte("different ZIP"))
		signature, err := Sign(key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(bytes.NewReader(raw), signature, trust); err == nil || !strings.Contains(err.Error(), "signature does not match") {
			t.Fatalf("expected signature failure before ZIP parsing, got %v", err)
		}
	})
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type infiniteZeros struct{}

func (infiniteZeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestWriterFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source io.Reader
	}{
		{"read failure", failingReader{}},
		{"member limit", infiniteZeros{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := NewWriter(io.Discard)
			_, err := w.Add("evidence.txt", tc.source)
			if err == nil {
				t.Fatal("expected Add to fail")
			}
			if err := w.Close(Manifest{Version: Version, TrailID: "trail"}); err == nil {
				t.Fatal("writer finalized an incomplete archive")
			}
		})
	}
	t.Run("destination error", func(t *testing.T) {
		w := NewWriter(failingWriter{})
		if err := w.Close(Manifest{Version: Version, TrailID: "trail"}); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("expected close to propagate destination failure, got %v", err)
		}
	})
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
