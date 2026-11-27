// Package auditpack writes and verifies versioned offline audit archives.
package auditpack

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"

	"fides/pkg/ledger"
)

const (
	Version           = 1
	SignatureHeader   = "X-Fides-Audit-Signature"
	MaxSignatureBytes = 4 << 10
	MaxArchiveBytes   = 128 << 20
	MaxMemberBytes    = 32 << 20
	maxExpandedBytes  = 256 << 20
	maxMembers        = 4096
	signatureDomain   = "fides:audit-pack:v1\x00"
	manifestName      = "manifest.json"
)

type Member struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Manifest struct {
	Version     int            `json:"version"`
	TrailID     string         `json:"trail_id"`
	ChainHead   string         `json:"chain_head"`
	Coverage    ledger.Verdict `json:"coverage"`
	Members     []Member       `json:"members"`
	Attachments []Attachment   `json:"attachments"`
}

type ChainRecord struct {
	ID             string       `json:"id"`
	ArtifactSHA256 *string      `json:"artifact_sha256,omitempty"`
	Entry          ledger.Entry `json:"entry"`
}

type Anchor struct {
	Head  string `json:"head"`
	Token []byte `json:"token"`
}

type Attachment struct {
	ID            string `json:"id"`
	AttestationID string `json:"attestation_id"`
	Name          string `json:"name"`
	SHA256        string `json:"sha256"`
	Member        string `json:"member"`
	Size          int64  `json:"size"`
}

type detachedSignature struct {
	Version   int    `json:"version"`
	KeyID     string `json:"key_id"`
	Signature []byte `json:"signature"`
}

// Sign signs the SHA-256 digest of the completed ZIP, including ZIP metadata.
func Sign(key ed25519.PrivateKey, digest []byte) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize || len(digest) != sha256.Size {
		return nil, errors.New("audit pack requires an Ed25519 private key and a SHA-256 digest")
	}
	public := key.Public().(ed25519.PublicKey)
	return json.Marshal(detachedSignature{Version, keyID(public), ed25519.Sign(key, signatureMessage(digest))})
}

func keyID(key ed25519.PublicKey) string {
	digest := sha256.Sum256(key)
	return hex.EncodeToString(digest[:])
}

func signatureMessage(digest []byte) []byte {
	return append([]byte(signatureDomain), digest...)
}

// Writer streams one ZIP. A failed Add or Close invalidates the entire output.
type Writer struct {
	zip      *zip.Writer
	members  []Member
	seen     map[string]Member
	expanded int64
	err      error
	closed   bool
}

func NewWriter(dst io.Writer) *Writer {
	return &Writer{zip: zip.NewWriter(&boundedWriter{dst, MaxArchiveBytes}), seen: make(map[string]Member)}
}

func (w *Writer) Add(name string, source io.Reader) (m Member, err error) {
	if w.closed {
		return Member{}, errors.New("audit pack writer is closed")
	}
	if w.err != nil {
		return Member{}, w.err
	}
	defer func() { w.err = err }()
	if !validName(name) || name == manifestName || len(w.members) >= maxMembers-1 {
		return Member{}, fmt.Errorf("invalid audit pack member or member limit reached: %q", name)
	}
	if _, ok := w.seen[name]; ok {
		return Member{}, fmt.Errorf("duplicate audit pack member %q", name)
	}
	m, err = w.writeMember(name, source)
	if err != nil {
		return Member{}, err
	}
	w.members = append(w.members, m)
	w.seen[name] = m
	return m, nil
}

// Close writes the manifest and finishes the ZIP. Members may be omitted to
// use the exact list recorded by Add.
func (w *Writer) Close(manifest Manifest) error {
	if w.closed {
		return errors.New("audit pack writer is closed")
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	if manifest.Members == nil {
		manifest.Members = w.members
	}
	listed, err := memberIndex(manifest.Members)
	if err != nil {
		return err
	}
	if !maps.Equal(listed, w.seen) {
		return errors.New("manifest members do not match archive members")
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if _, err := w.writeMember(manifestName, bytes.NewReader(raw)); err != nil {
		return err
	}
	return w.zip.Close()
}

func (w *Writer) writeMember(name string, source io.Reader) (Member, error) {
	dst, err := w.zip.Create(name)
	if err != nil {
		return Member{}, err
	}
	h := sha256.New()
	limit := min(MaxMemberBytes, maxExpandedBytes-w.expanded)
	n, err := io.Copy(io.MultiWriter(dst, h), io.LimitReader(source, limit+1))
	if err != nil {
		return Member{}, fmt.Errorf("write %q: %w", name, err)
	}
	if n > limit {
		return Member{}, fmt.Errorf("audit pack size limit exceeded writing %q", name)
	}
	w.expanded += n
	return Member{Name: name, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}, nil
}

type boundedWriter struct {
	dst       io.Writer
	remaining int64
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errors.New("audit pack archive size limit exceeded")
	}
	n, err := w.dst.Write(p)
	w.remaining -= int64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

// Only portable, canonical file paths are used in v1 ZIPs.
func validName(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	for part := range strings.SplitSeq(name, "/") {
		if part == "" || part[0] == '.' || part[len(part)-1] == '.' {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validDigest(s string) bool {
	if len(s) != sha256.Size*2 || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func memberIndex(members []Member) (map[string]Member, error) {
	if len(members) >= maxMembers {
		return nil, errors.New("manifest member limit exceeded")
	}
	index := make(map[string]Member, len(members))
	for _, m := range members {
		if !validName(m.Name) || m.Name == manifestName || !validDigest(m.SHA256) || m.Size < 0 || m.Size > MaxMemberBytes {
			return nil, fmt.Errorf("invalid manifest member %q", m.Name)
		}
		if _, exists := index[m.Name]; exists {
			return nil, fmt.Errorf("duplicate manifest member %q", m.Name)
		}
		index[m.Name] = m
	}
	return index, nil
}
