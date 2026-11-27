package auditpack

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"fides/pkg/cosignverify"
	"fides/pkg/ledger"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

type attachmentCommitment struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type evidenceCommitment struct {
	ArtifactSHA256      *string `json:"artifact_sha256"`
	SignedBy            *string `json:"signed_by"`
	Signature           *string `json:"signature"`
	SignatureAlgorithm  *string `json:"signature_algorithm"`
	ManifestationReason *string `json:"manifestation_reason"`
	Policy              *struct {
		ID           string   `json:"id"`
		Schema       *string  `json:"schema"`
		SchemaSHA256 string   `json:"oversize_schema_sha256,omitempty"`
		Rules        []string `json:"jq_rules"`
	} `json:"policy"`
	Attachments []attachmentCommitment `json:"attachments"`
}

func (r *Result) verifyEvidence(files map[string]*zip.File, trust Trust) error {
	var trail struct {
		ID string `json:"id"`
	}
	var records []ChainRecord
	var anchors []Anchor
	var artifacts, approvals []map[string]json.RawMessage
	if err := readJSONMember(files, "trail.json", &trail, false); err != nil {
		return err
	}
	if trail.ID != r.Manifest.TrailID {
		return errors.New("trail metadata does not match the manifest")
	}
	if err := readJSONMember(files, "artifacts.json", &artifacts, false); err != nil {
		return err
	}
	if err := readJSONMember(files, "approvals.json", &approvals, false); err != nil {
		return err
	}
	if err := readJSONMember(files, "chain.json", &records, true); err != nil {
		return err
	}
	if err := readJSONMember(files, "anchors.json", &anchors, true); err != nil {
		return err
	}
	chain := make([]ledger.Entry, 0, len(records))
	hashes := make(map[string]bool, len(records))
	versions := make(map[string]int, len(records))
	head := ""
	for _, record := range records {
		if _, seen := versions[record.ID]; seen || record.ID == "" || record.Entry.TrailID != trail.ID ||
			!json.Valid([]byte(record.Entry.Payload)) {
			return fmt.Errorf("invalid or duplicate chain record %q", record.ID)
		}
		entry := record.Entry
		if entry.ContentHash != "" {
			if !validDigest(entry.ContentHash) || hashes[entry.ContentHash] {
				return fmt.Errorf("invalid or duplicate content hash at %q", record.ID)
			}
			head = entry.ContentHash
			hashes[head] = true
		} else if entry.PrevHash != "" {
			return fmt.Errorf("unchained record %q has a previous hash", record.ID)
		}
		if entry.Version < 2 {
			entry.Payload = ledger.CanonicalJSON(entry.Payload)
		}
		chain = append(chain, entry)
		versions[record.ID] = entry.Version
	}
	coverage := ledger.Verify(chain)
	if !coverage.Valid {
		return fmt.Errorf("invalid chain at record %d: %s", coverage.BrokenAt, coverage.Reason)
	}
	if coverage != r.Manifest.Coverage || head != r.Manifest.ChainHead {
		return errors.New("chain head or coverage does not match the manifest")
	}
	if coverage.UnhashedCount > 0 || coverage.LegacyCount > 0 {
		r.Incomplete = append(r.Incomplete, fmt.Sprintf("ledger has %d unhashed and %d legacy attestations", coverage.UnhashedCount, coverage.LegacyCount))
	}

	committed := make(map[string]Attachment)
	verifier := cosignverify.NewSigstoreVerifier()
	for _, record := range records {
		var inputs evidenceCommitment
		if record.Entry.Version == 2 {
			if err := decodeJSON([]byte(record.Entry.Evidence), &inputs, true); err != nil {
				return fmt.Errorf("invalid v2 evidence at %q: %w", record.ID, err)
			}
			if inputs.Attachments == nil {
				return fmt.Errorf("v2 evidence at %q has no attachment list", record.ID)
			}
			for _, a := range inputs.Attachments {
				if _, exists := committed[a.ID]; exists || a.ID == "" || !validDigest(a.SHA256) || a.Size < 0 {
					return fmt.Errorf("invalid or duplicate attachment commitment %q", a.ID)
				}
				committed[a.ID] = Attachment{a.ID, record.ID, a.Name, a.SHA256, "attachments/" + a.ID, a.Size}
			}
			if policy := inputs.Policy; policy != nil {
				if policy.ID == "" || (policy.Schema != nil && !json.Valid([]byte(*policy.Schema))) {
					return fmt.Errorf("invalid historical policy at %q", record.ID)
				}
				if policy.SchemaSHA256 != "" {
					if !validDigest(policy.SchemaSHA256) || policy.Schema != nil {
						return fmt.Errorf("invalid historical policy digest at %q", record.ID)
					}
					r.Incomplete = append(r.Incomplete, "missing historical policy schema for "+record.ID)
				}
			}
		}
		missing, err := verifySignerProof(record, inputs.ArtifactSHA256, trust.Signers, verifier)
		if err != nil {
			return fmt.Errorf("signer proof at %q: %w", record.ID, err)
		}
		if missing {
			r.Incomplete = append(r.Incomplete, "missing signer proof for "+record.ID)
		}
	}
	if err := r.verifyAttachments(files, versions, committed); err != nil {
		return err
	}

	currentAnchored := false
	for _, anchor := range anchors {
		if !hashes[anchor.Head] {
			return fmt.Errorf("timestamp references a head outside the chain: %q", anchor.Head)
		}
		if err := verifyTimestamp(anchor, trust.TSARoots); err != nil {
			return fmt.Errorf("timestamp for %s: %w", anchor.Head, err)
		}
		currentAnchored = currentAnchored || anchor.Head == head
	}
	if !currentAnchored {
		r.Incomplete = append(r.Incomplete, "missing timestamp for the current chain head")
	}
	return nil
}

func (r *Result) verifyAttachments(files map[string]*zip.File, versions map[string]int, committed map[string]Attachment) error {
	index, err := memberIndex(r.Manifest.Members)
	if err != nil {
		return err
	}
	ids, paths := make(map[string]bool), make(map[string]bool)
	for _, a := range r.Manifest.Attachments {
		version, belongs := versions[a.AttestationID]
		if !validName("attachments/"+a.ID) || strings.Contains(a.ID, "/") || ids[a.ID] || !belongs || a.Size < 0 {
			return fmt.Errorf("invalid or duplicate attachment %q", a.ID)
		}
		ids[a.ID] = true
		want, bound := committed[a.ID]
		if version == 2 || bound {
			if !bound || a != want {
				return fmt.Errorf("attachment %q does not match its v2 commitment", a.ID)
			}
			delete(committed, a.ID)
		}
		if a.Member == "" {
			if validDigest(strings.ToLower(a.SHA256)) {
				return fmt.Errorf("attachment %q has a digest but no member", a.ID)
			}
			r.Incomplete = append(r.Incomplete, "missing historical attachment bytes for "+a.ID)
			continue
		}
		member, listed := index[a.Member]
		if a.Member != "attachments/"+a.ID || !listed || !strings.EqualFold(member.SHA256, a.SHA256) || member.Size != a.Size {
			return fmt.Errorf("attachment %q does not match its archived member", a.ID)
		}
		paths[a.Member] = true
	}
	if len(committed) != 0 {
		return errors.New("missing attachments required by v2 chain commitments")
	}
	for path := range files {
		if strings.HasPrefix(path, "attachments/") && !paths[path] {
			return fmt.Errorf("unreferenced attachment member %q", path)
		}
	}
	return nil
}

func verifySignerProof(record ChainRecord, artifact *string, policies map[string]cosignverify.OfflineOptions, verifier *cosignverify.SigstoreVerifier) (missing bool, err error) {
	entry := record.Entry
	if !strings.HasPrefix(strings.TrimSpace(entry.Payload), "{") {
		if entry.TypeName == "cosign-verification" {
			return false, errors.New("cosign payload must be an object")
		}
		return false, nil
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal([]byte(entry.Payload), &payload); err != nil {
		return false, err
	}

	var digest string
	var proof cosignverify.Proof
	providerRaw, provider := payload["signer_proof"]
	cosignRaw, cosign := payload["proof"]
	cosign = cosign && entry.TypeName == "cosign-verification"
	switch {
	case provider && cosign:
		return false, errors.New("multiple signer proof formats on one attestation")
	case provider:
		var retained struct {
			Version int    `json:"version"`
			Format  string `json:"format"`
			Digest  string `json:"artifact_sha256"`
			Bundle  []byte `json:"bundle_base64"`
		}
		if err := decodeJSON(providerRaw, &retained, true); err != nil {
			return false, err
		}
		if retained.Version != 1 || retained.Format != "sigstore-dsse-bundle" || len(retained.Bundle) == 0 {
			return false, errors.New("unsupported or empty provider signer proof")
		}
		// The provider format promises an in-toto DSSE subject. A valid
		// message-signature bundle alone cannot establish that claim.
		var dsse struct {
			Envelope json.RawMessage `json:"dsseEnvelope"`
		}
		if err := json.Unmarshal(retained.Bundle, &dsse); err != nil || len(dsse.Envelope) == 0 || bytes.Equal(dsse.Envelope, []byte("null")) {
			return false, errors.New("provider signer proof is not a DSSE bundle")
		}
		digest, proof.Bundle = retained.Digest, retained.Bundle
	case cosign:
		if err := json.Unmarshal(payload["digest"], &digest); err != nil {
			return false, fmt.Errorf("invalid cosign digest: %w", err)
		}
		if err := decodeJSON(cosignRaw, &proof, true); err != nil {
			return false, err
		}
	default:
		_, fromProvider := payload["provider"]
		return entry.TypeName == "cosign-verification" || (entry.TypeName == "slsa-provenance" && fromProvider), nil
	}

	digest = strings.ToLower(digest)
	if !validDigest(digest) {
		return false, errors.New("missing or invalid signer artifact digest")
	}
	if entry.Version == 2 && (artifact == nil || !strings.EqualFold(*artifact, digest)) {
		return false, errors.New("signer digest does not match the committed artifact")
	}
	policy, ok := policies[digest]
	if !ok {
		return false, fmt.Errorf("no local signer policy for artifact %s", digest)
	}
	if policy.Digest != "" && policy.Digest != digest {
		return false, fmt.Errorf("local signer policy digest does not match artifact %s", digest)
	}
	if policy.KeyPath != "" && (policy.Signer != "" || policy.Issuer != "") {
		return false, errors.New("local signer policy mixes a pinned key with a keyless identity")
	}
	policy.Digest = digest
	verdict, err := verifier.VerifyOffline(&proof, policy)
	if err != nil {
		return false, err
	}
	if !verdict.Verified {
		return false, errors.New(verdict.Reason)
	}
	return false, nil
}

func verifyTimestamp(anchor Anchor, roots *x509.CertPool) error {
	if roots == nil {
		return errors.New("local TSA roots are required")
	}
	if len(anchor.Token) > 1<<20 {
		return errors.New("timestamp token exceeds the size limit")
	}
	t, err := timestamp.ParseResponse(anchor.Token)
	if err != nil {
		return err
	}
	imprint := sha256.Sum256([]byte(anchor.Head))
	if t.HashAlgorithm != crypto.SHA256 || !bytes.Equal(t.HashedMessage, imprint[:]) || t.Time.IsZero() {
		return errors.New("timestamp does not bind the expected head and time")
	}
	// ParseResponse checks the CMS signature when certificates are present.
	// Require the certificate selected by CMS, not another embedded TSA cert.
	cms, err := pkcs7.Parse(t.RawToken)
	if err != nil {
		return err
	}
	signer := cms.GetOnlySigner()
	if signer == nil {
		return errors.New("timestamp token must have one identified signing certificate")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range cms.Certificates {
		if cert != signer {
			intermediates.AddCert(cert)
		}
	}
	if !slices.Contains(signer.ExtKeyUsage, x509.ExtKeyUsageTimeStamping) {
		return errors.New("signing certificate is missing the timestamping key usage")
	}
	_, err = signer.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: t.Time,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	})
	return err
}
