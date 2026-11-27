package auditpack

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"fides/pkg/cosignverify"
)

// Trust comes from the auditor's local configuration. Signers maps unprefixed
// SHA-256 artifact digests to pinned keys or keyless identity and root policy.
type Trust struct {
	ArchiveKeys []ed25519.PublicKey
	TSARoots    *x509.CertPool
	Signers     map[string]cosignverify.OfflineOptions
}

// Result reports verified facts and any gaps that make the evidence incomplete.
// A verification error always takes precedence over missing historical evidence.
type Result struct {
	Manifest   Manifest
	Incomplete []string
}

// Verify authenticates the exact ZIP bytes, then verifies every member and
// present proof using only the explicitly supplied local trust.
func Verify(source io.Reader, signature []byte, trust Trust) (Result, error) {
	sig, err := parseSignature(signature)
	if err != nil {
		return Result{}, err
	}
	var key ed25519.PublicKey
	for _, pub := range trust.ArchiveKeys {
		if len(pub) == ed25519.PublicKeySize && keyID(pub) == sig.KeyID {
			key = pub
			break
		}
	}
	if key == nil {
		return Result{}, fmt.Errorf("untrusted archive signing key %s", sig.KeyID)
	}
	raw, err := io.ReadAll(io.LimitReader(source, MaxArchiveBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("read archive: %w", err)
	}
	if len(raw) > MaxArchiveBytes {
		return Result{}, errors.New("audit pack archive size limit exceeded")
	}
	digest := sha256.Sum256(raw)
	if !ed25519.Verify(key, signatureMessage(digest[:]), sig.Signature) {
		return Result{}, errors.New("audit pack archive signature does not match its bytes")
	}

	manifest, files, err := verifyZIP(raw)
	if err != nil {
		return Result{}, err
	}
	result := Result{Manifest: manifest}
	if err := result.verifyEvidence(files, trust); err != nil {
		return Result{}, err
	}
	return result, nil
}

// ValidateSignatureFormat checks a detached signature envelope without trust or ZIP data.
func ValidateSignatureFormat(signature []byte) error {
	_, err := parseSignature(signature)
	return err
}

func parseSignature(signature []byte) (detachedSignature, error) {
	var sig detachedSignature
	if len(signature) > MaxSignatureBytes || decodeJSON(signature, &sig, true) != nil ||
		sig.Version != Version || !validDigest(sig.KeyID) || len(sig.Signature) != ed25519.SignatureSize {
		return detachedSignature{}, errors.New("invalid detached audit pack signature")
	}
	return sig, nil
}

func verifyZIP(raw []byte) (Manifest, map[string]*zip.File, error) {
	if err := checkDirectory(raw); err != nil {
		return Manifest{}, nil, err
	}
	z, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("read ZIP: %w", err)
	}
	files := make(map[string]*zip.File, len(z.File))
	var total uint64
	for _, f := range z.File {
		if !validName(f.Name) || !f.Mode().IsRegular() || (f.Method != zip.Store && f.Method != zip.Deflate) ||
			f.UncompressedSize64 > MaxMemberBytes {
			return Manifest{}, nil, fmt.Errorf("invalid ZIP member %q", f.Name)
		}
		if _, exists := files[f.Name]; exists {
			return Manifest{}, nil, fmt.Errorf("duplicate ZIP member %q", f.Name)
		}
		total += f.UncompressedSize64
		if total > maxExpandedBytes {
			return Manifest{}, nil, errors.New("audit pack expanded size limit exceeded")
		}
		files[f.Name] = f
	}
	var manifest Manifest
	if err := readJSONMember(files, manifestName, &manifest, true); err != nil {
		return Manifest{}, nil, err
	}
	if manifest.Version != Version || manifest.TrailID == "" {
		return Manifest{}, nil, errors.New("unsupported manifest version or missing trail ID")
	}
	index, err := memberIndex(manifest.Members)
	if err != nil {
		return Manifest{}, nil, err
	}
	if len(files) != len(index)+1 {
		return Manifest{}, nil, errors.New("ZIP and manifest have different member counts")
	}
	for _, member := range manifest.Members {
		f := files[member.Name]
		if f == nil || f.UncompressedSize64 != uint64(member.Size) { // #nosec G115 -- memberIndex validates size
			return Manifest{}, nil, fmt.Errorf("missing ZIP member or size mismatch: %q", member.Name)
		}
		h := sha256.New()
		if err := copyMember(h, f); err != nil {
			return Manifest{}, nil, err
		}
		if hex.EncodeToString(h.Sum(nil)) != member.SHA256 {
			return Manifest{}, nil, fmt.Errorf("SHA-256 mismatch for %q", member.Name)
		}
	}
	return manifest, files, nil
}

// Preflight the v1 central directory before archive/zip allocates its file
// index. Its reader walks the directory even when the declared count is low.
func checkDirectory(raw []byte) error {
	const (
		endHeader     = "PK\x05\x06"
		centralHeader = "PK\x01\x02"
		endSize       = 22
		centralSize   = 46
	)
	u16, u32 := binary.LittleEndian.Uint16, binary.LittleEndian.Uint32
	end := bytes.LastIndex(raw[max(0, len(raw)-endSize-65535):], []byte(endHeader))
	if end < 0 {
		return errors.New("missing ZIP end of central directory")
	}
	end += max(0, len(raw)-endSize-65535)
	tail := raw[end:]
	if len(tail) < endSize || len(tail) != endSize+int(u16(tail[20:])) || u32(tail[4:]) != 0 {
		return errors.New("invalid ZIP end of central directory")
	}
	count := int(u16(tail[10:]))
	offset, size := int64(u32(tail[16:])), int64(u32(tail[12:]))
	if count < 1 || count > maxMembers || count != int(u16(tail[8:])) || offset+size != int64(end) {
		return errors.New("invalid ZIP central directory bounds")
	}
	dir := raw[offset:end]
	locals := make([][2]int, 0, count)
	for range count {
		if len(dir) < centralSize || string(dir[:4]) != centralHeader {
			return errors.New("invalid ZIP central directory record")
		}
		n := centralSize + int(u16(dir[28:])) + int(u16(dir[30:])) + int(u16(dir[32:]))
		if n > len(dir) {
			return errors.New("truncated ZIP central directory record")
		}
		local, err := checkLocalHeader(raw[:offset], dir[:n])
		if err != nil {
			return err
		}
		locals = append(locals, local)
		dir = dir[n:]
	}
	if len(dir) != 0 {
		return errors.New("unexpected records in ZIP central directory")
	}
	slices.SortFunc(locals, func(a, b [2]int) int { return a[0] - b[0] })
	next := 0
	for _, local := range locals {
		if local[0] != next {
			return errors.New("unlisted or overlapping ZIP member data")
		}
		next = local[1]
	}
	if int64(next) != offset {
		return errors.New("unlisted ZIP member data before central directory")
	}
	return nil
}

// Match each on-disk record to its directory record. Sequential ZIP readers
// must not see different names or additional members.
func checkLocalHeader(data, central []byte) ([2]int, error) {
	const localSize = 30
	invalid := errors.New("ZIP local member does not match its central directory record")
	u16, u32 := binary.LittleEndian.Uint16, binary.LittleEndian.Uint32
	start := int64(u32(central[42:]))
	if start+localSize > int64(len(data)) {
		return [2]int{}, invalid
	}
	local := data[start:]
	flags := u16(local[6:])
	if string(local[:4]) != "PK\x03\x04" || flags&1 != 0 || !bytes.Equal(local[6:10], central[8:12]) {
		return [2]int{}, invalid
	}
	nameEnd := localSize + int(u16(local[26:]))
	payloadAt := nameEnd + int(u16(local[28:]))
	dataEnd := int64(payloadAt) + int64(u32(central[20:]))
	if dataEnd > int64(len(local)) || !bytes.Equal(local[localSize:nameEnd], central[46:46+int(u16(central[28:]))]) {
		return [2]int{}, invalid
	}
	sizes := central[16:28] // CRC, compressed size, expanded size.
	if flags&8 == 0 {
		if !bytes.Equal(local[14:26], sizes) {
			return [2]int{}, invalid
		}
	} else {
		descriptor := local[dataEnd:]
		switch {
		case len(descriptor) >= 16 && string(descriptor[:4]) == "PK\x07\x08" && bytes.Equal(descriptor[4:16], sizes):
			dataEnd += 16
		case len(descriptor) >= 12 && bytes.Equal(descriptor[:12], sizes):
			dataEnd += 12
		default:
			return [2]int{}, invalid
		}
	}
	return [2]int{int(start), int(start + dataEnd)}, nil
}

func copyMember(dst io.Writer, file *zip.File) error {
	r, err := file.Open()
	if err != nil {
		return fmt.Errorf("open %q: %w", file.Name, err)
	}
	defer r.Close()
	// verifyZIP bounds all sizes before opening any member.
	size := int64(file.UncompressedSize64) // #nosec G115 -- verified against MaxMemberBytes
	n, err := io.Copy(dst, io.LimitReader(r, size+1))
	if err != nil {
		return fmt.Errorf("read %q: %w", file.Name, err)
	}
	if n != size {
		return fmt.Errorf("size mismatch reading %q", file.Name)
	}
	return nil
}

func readJSONMember(files map[string]*zip.File, name string, dst any, strict bool) error {
	f := files[name]
	if f == nil {
		return fmt.Errorf("missing required member %q", name)
	}
	var raw bytes.Buffer
	if err := copyMember(&raw, f); err != nil {
		return err
	}
	if err := decodeJSON(raw.Bytes(), dst, strict); err != nil {
		return fmt.Errorf("decode %q: %w", name, err)
	}
	return nil
}

func decodeJSON(raw []byte, dst any, strict bool) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("unexpected data after JSON value")
	}
	if strict {
		fields := json.NewDecoder(bytes.NewReader(raw))
		fields.UseNumber()
		return uniqueJSONFields(fields)
	}
	return nil
}

// The typed decoder has already validated the JSON document.
func uniqueJSONFields(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name := strings.ToLower(key.(string))
			if seen[name] {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[name] = true
			if err := uniqueJSONFields(d); err != nil {
				return err
			}
		}
	case json.Delim('['):
		for d.More() {
			if err := uniqueJSONFields(d); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	_, err = d.Token()
	return err
}
