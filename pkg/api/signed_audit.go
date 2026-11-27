package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"fides/pkg/auditpack"
	"fides/pkg/db"
	"fides/pkg/storage"

	"github.com/google/uuid"
)

const auditRecordLimit = 10_000

var (
	errAuditLimit = errors.New("audit pack exceeds export limits")
	errAuditKey   = errors.New("audit pack signing key unavailable")
)

func (s *Server) handleSignedAuditPack(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	trailID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid trail id", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	snapshot, err := s.readSignedAuditSnapshot(ctx, orgID, trailID)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "trail not found", http.StatusNotFound)
		return
	}
	if err != nil {
		internalError(w, err)
		return
	}
	key, err := loadAuditPackKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	file, err := os.CreateTemp("", "fides-audit-*.zip")
	if err != nil {
		internalError(w, err)
		return
	}
	defer func() {
		if err := os.Remove(file.Name()); err != nil {
			log.Printf("audit pack staging cleanup failed: %v", err)
		}
	}()
	defer file.Close()

	if err := s.stageSignedAuditPack(ctx, file, orgID, snapshot); err != nil {
		internalError(w, err)
		return
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		internalError(w, err)
		return
	}
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		internalError(w, err)
		return
	}
	signature, err := auditpack.Sign(key, digest.Sum(nil))
	if err != nil {
		internalError(w, err)
		return
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		internalError(w, err)
		return
	}
	if ctx.Err() != nil {
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "trail-"+trailID.String()+"-audit.zip"))
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set(auditpack.SignatureHeader, base64.StdEncoding.EncodeToString(signature))
	if _, err := io.Copy(w, file); err != nil {
		log.Printf("audit pack delivery failed: %v", err)
	}
}

func loadAuditPackKey() (ed25519.PrivateKey, error) {
	file, err := os.Open(os.Getenv("FIDES_AUDIT_PACK_PRIVATE_KEY_FILE")) // #nosec G304 G703 -- only the server operator supplies this path
	if err != nil {
		return nil, errAuditKey
	}
	defer file.Close()
	const maxPEM = 4096
	raw, err := io.ReadAll(io.LimitReader(file, maxPEM+1))
	if err != nil || len(raw) > maxPEM {
		return nil, errAuditKey
	}
	raw = bytes.TrimSpace(raw)
	block, rest := pem.Decode(raw)
	if !bytes.HasPrefix(raw, []byte("-----BEGIN PRIVATE KEY-----")) ||
		block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errAuditKey
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return nil, errAuditKey
	}
	return key, nil
}

type auditAttachmentRow struct {
	auditpack.Attachment
	storagePath string
	version     int
}

type auditJSONFile struct {
	name string
	data []byte
}

type auditSnapshot struct {
	manifest    auditpack.Manifest
	members     []auditJSONFile
	attachments []auditAttachmentRow
}

func (s *Server) readSignedAuditSnapshot(ctx context.Context, orgID, trailID uuid.UUID) (auditSnapshot, error) {
	tx, err := db.BeginTx(ctx, s.DB, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return auditSnapshot{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SELECT set_config('app.current_org', $1, true)", orgID.String()); err != nil {
		return auditSnapshot{}, err
	}

	var trail json.RawMessage
	if err := tx.QueryRowContext(ctx, `SELECT to_jsonb(tr) || jsonb_build_object('org_id', f.org_id)
		FROM trails tr JOIN flows f ON f.id = tr.flow_id WHERE tr.id = $1 AND f.org_id = $2`,
		trailID, orgID).Scan(&trail); err != nil {
		return auditSnapshot{}, err
	}

	// The ZIP writer bounds each member. Also bound chain input before the
	// shared reader loads and canonicalizes the trail's JSON.
	var chainFits bool
	if err := tx.QueryRowContext(ctx, `SELECT count(*) <= $2 AND
		COALESCE(sum(octet_length(payload::text) + COALESCE(octet_length(evidence_inputs::text), 0)), 0) <= $3
		FROM attestations WHERE trail_id = $1`, trailID, auditRecordLimit, auditpack.MaxMemberBytes).Scan(&chainFits); err != nil {
		return auditSnapshot{}, err
	}
	if !chainFits {
		return auditSnapshot{}, errAuditLimit
	}
	entries, err := s.readTrailChain(db.WithQuerier(ctx, tx), trailID)
	if err != nil {
		return auditSnapshot{}, err
	}
	coverage := verifyTrailEntries(entries)
	if !coverage.Valid {
		return auditSnapshot{}, fmt.Errorf("audit pack chain verification failed: %s", coverage.Reason)
	}

	manifest := auditpack.Manifest{
		Version: auditpack.Version, TrailID: trailID.String(), Coverage: coverage,
		Attachments: []auditpack.Attachment{},
	}
	chain := make([]auditpack.ChainRecord, 0, len(entries))
	for _, entry := range entries {
		chain = append(chain, auditpack.ChainRecord{ID: entry.id, Entry: entry.Entry})
		if entry.ContentHash != "" {
			manifest.ChainHead = entry.ContentHash
		}
	}

	chainJSON, err := json.Marshal(chain)
	if err != nil {
		return auditSnapshot{}, err
	}
	snapshot := auditSnapshot{
		manifest: manifest,
		members:  []auditJSONFile{{"trail.json", trail}, {"chain.json", chainJSON}},
	}
	for _, member := range []struct {
		name, query string
		scan        func(*sql.Rows) ([]byte, error)
	}{
		{"artifacts.json", `SELECT to_jsonb(a) FROM artifacts a
			WHERE a.org_id = $2 AND (a.trail_id = $1 OR a.sha256 IN (
				SELECT artifact_sha256 FROM attestations WHERE trail_id = $1
			)) ORDER BY a.created_at, a.sha256`, scanAuditJSON},
		{"approvals.json", `SELECT to_jsonb(a) FROM trail_approvals a
			WHERE a.trail_id = $1 AND a.org_id = $2 ORDER BY a.created_at, a.id`, scanAuditJSON},
		{"anchors.json", `SELECT chain_head_hash, timestamp_token
			FROM trail_anchors WHERE trail_id = $1 AND org_id = $2 ORDER BY anchored_at, id`, scanAuditAnchor},
	} {
		data, err := auditJSONArray(ctx, tx, member.query, trailID, orgID, member.scan)
		if err != nil {
			return auditSnapshot{}, err
		}
		snapshot.members = append(snapshot.members, auditJSONFile{member.name, data})
	}
	snapshot.attachments, err = readAuditAttachments(ctx, tx, trailID)
	if err != nil {
		return auditSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return auditSnapshot{}, err
	}
	return snapshot, nil
}

func (s *Server) stageSignedAuditPack(ctx context.Context, dest io.Writer, orgID uuid.UUID, snapshot auditSnapshot) error {
	zw := auditpack.NewWriter(dest)
	for _, member := range snapshot.members {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := zw.Add(member.name, bytes.NewReader(member.data)); err != nil {
			return err
		}
	}
	for _, attachment := range snapshot.attachments {
		if err := ctx.Err(); err != nil {
			return err
		}
		if attachment.Size < 0 || attachment.Size > auditpack.MaxMemberBytes {
			return errAuditLimit
		}
		hash, err := hex.DecodeString(attachment.SHA256)
		committed := attachment.version == 2
		if len(hash) != sha256.Size || err != nil || (committed && attachment.SHA256 != strings.ToLower(attachment.SHA256)) {
			if committed {
				return errors.New("invalid committed audit attachment digest")
			}
			// Older rows can have placeholder hashes. Preserve their metadata
			// without treating current storage bytes as historical evidence.
			snapshot.manifest.Attachments = append(snapshot.manifest.Attachments, attachment.Attachment)
			continue
		}
		attachment.Member = "attachments/" + attachment.ID
		if err := s.addAuditAttachment(ctx, orgID, attachment, zw); err != nil {
			return err
		}
		snapshot.manifest.Attachments = append(snapshot.manifest.Attachments, attachment.Attachment)
	}
	return zw.Close(snapshot.manifest)
}

func scanAuditJSON(rows *sql.Rows) ([]byte, error) {
	var raw []byte
	err := rows.Scan(&raw)
	return raw, err
}

func scanAuditAnchor(rows *sql.Rows) ([]byte, error) {
	var anchor auditpack.Anchor
	if err := rows.Scan(&anchor.Head, &anchor.Token); err != nil {
		return nil, err
	}
	return json.Marshal(anchor)
}

func auditJSONArray(ctx context.Context, tx *sql.Tx, query string, trailID, orgID uuid.UUID, scan func(*sql.Rows) ([]byte, error)) ([]byte, error) {
	rows, err := tx.QueryContext(ctx, query, trailID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var data bytes.Buffer
	data.WriteByte('[')
	for i := 0; rows.Next(); i++ {
		raw, err := scan(rows)
		if err != nil {
			return nil, err
		}
		if i >= auditRecordLimit || data.Len()+len(raw)+2 > auditpack.MaxMemberBytes {
			return nil, errAuditLimit
		}
		if i > 0 {
			data.WriteByte(',')
		}
		data.Write(raw)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	data.WriteByte(']')
	return data.Bytes(), nil
}

func readAuditAttachments(ctx context.Context, tx *sql.Tx, trailID uuid.UUID) ([]auditAttachmentRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT e.id, a.id, e.file_name, e.file_hash, e.file_size, e.storage_path, a.hash_version
		FROM evidence_attachments e JOIN attestations a ON a.id = e.attestation_id
		WHERE a.trail_id = $1 ORDER BY e.id`, trailID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var attachments []auditAttachmentRow
	for rows.Next() {
		var a auditAttachmentRow
		if err := rows.Scan(&a.ID, &a.AttestationID, &a.Name, &a.SHA256, &a.Size, &a.storagePath, &a.version); err != nil {
			return nil, err
		}
		if len(attachments) >= auditRecordLimit {
			return nil, errAuditLimit
		}
		attachments = append(attachments, a)
	}
	return attachments, rows.Err()
}

func (s *Server) addAuditAttachment(ctx context.Context, orgID uuid.UUID, a auditAttachmentRow, zw *auditpack.Writer) error {
	bucket, key, err := auditAttachmentLocation(s.Storage, orgID, a)
	if err != nil {
		return err
	}
	object, err := s.Storage.Download(ctx, bucket, key)
	if err != nil {
		return fmt.Errorf("download audit attachment %s: %w", a.ID, err)
	}
	member, writeErr := zw.Add(a.Member, io.LimitReader(object, a.Size+1))
	if err := errors.Join(writeErr, object.Close()); err != nil {
		return err
	}
	if member.Size != a.Size || !strings.EqualFold(member.SHA256, a.SHA256) {
		return fmt.Errorf("audit attachment %s does not match recorded size and digest", a.ID)
	}
	return nil
}

func auditAttachmentLocation(backend storage.StorageBackend, orgID uuid.UUID, a auditAttachmentRow) (string, string, error) {
	var scheme string
	switch backend.(type) {
	case *storage.LocalStorage:
		scheme = "local://"
	case *storage.S3Storage:
		scheme = "s3://"
	default:
		return "", "", errors.New("unsupported audit attachment storage backend")
	}
	bucket := os.Getenv("AWS_S3_BUCKET")
	if bucket == "" {
		bucket = "fides-evidence"
	}
	key, ok := strings.CutPrefix(a.storagePath, scheme+bucket+"/")
	parts := strings.Split(key, "/")
	valid := ok && path.Clean(key) == key && !strings.ContainsAny(key, "\\?#%")
	// Unkeyed recordings are scoped by their attestation UUID. Idempotent
	// recordings namespace the object under the owning organization UUID.
	if len(parts) == 2 {
		valid = valid && parts[0] == a.AttestationID
	} else if len(parts) == 5 {
		operation, err := uuid.Parse(parts[2])
		fingerprint, hexErr := hex.DecodeString(parts[3])
		valid = valid && parts[0] == "recordings" && parts[1] == orgID.String() &&
			err == nil && operation.String() == parts[2] && hexErr == nil && len(fingerprint) == sha256.Size
	} else {
		valid = false
	}
	if index, digest, found := strings.Cut(parts[len(parts)-1], "-"); found {
		n, err := strconv.ParseUint(index, 10, 32)
		valid = valid && err == nil && strconv.FormatUint(n, 10) == index && strings.EqualFold(digest, a.SHA256)
	} else {
		valid = false
	}
	if !valid {
		return "", "", fmt.Errorf("invalid storage location for audit attachment %s", a.ID)
	}
	return bucket, key, nil
}
