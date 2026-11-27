package api

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"fides/pkg/auditpack"
	"fides/pkg/auth"
	"fides/pkg/models"
	"fides/pkg/storage"

	"github.com/digitorus/timestamp"
	"github.com/google/uuid"
)

func TestSignedAuditPackIntegration(t *testing.T) {
	f := newRouteAuthFixture(t)
	t.Setenv("FIDES_LEDGER_EVIDENCE_V2", "true")
	t.Setenv("FIDES_RLS_ENABLED", "true")
	t.Setenv("AWS_S3_BUCKET", "audit-fixture")
	stageDir := t.TempDir()
	t.Setenv("TMPDIR", stageDir)
	local, err := storage.NewLocalStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f.server.Storage = local

	keyPath := filepath.Join(t.TempDir(), "signing.pem")
	t.Setenv("FIDES_AUDIT_PACK_PRIVATE_KEY_FILE", keyPath)
	key := writeAuditFixtureKey(t, keyPath)
	org, trail, artifact, referenced := f.own["org"], f.own["trail"], f.own["sha"], f.own["removeSHA"]
	mustExec(t, f.pool, `INSERT INTO artifacts (sha256,org_id,trail_id,name,type) VALUES
		($1,$2,$3,'audited-file','file'), ($4,$5,$3,'foreign-file','file'), ($6,$2,NULL,'referenced-file','file')`,
		artifact, org, trail, f.other["sha"], f.other["org"], referenced)
	mustExec(t, f.pool, `INSERT INTO trail_approvals (org_id,trail_id,approved_by,approver_kind) VALUES
		($1,$2,'audit@example.invalid','session'), ($3,$2,'foreign@example.invalid','session')`, org, trail, f.other["org"])
	policyID := uuid.New()
	mustExec(t, f.pool, `INSERT INTO attestation_types (id,org_id,name,schema,jq_rules)
		VALUES ($1,$2,'audit-policy','{"type":"object"}',ARRAY['.ok == true'])`, policyID, org)

	// Record real attachments through both supported upload key layouts.
	payload := []string{"exact keyed evidence\x00", "exact unkeyed evidence\n"}
	attestations := make([]models.Attestation, len(payload))
	for i, data := range payload {
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		for name, value := range map[string]string{
			"trail_id": trail, "artifact_sha256": []string{artifact, referenced}[i], "name": "audit-policy",
			"type_name": "audit-policy", "payload": `{"ok":true}`,
		} {
			if err := form.WriteField(name, value); err != nil {
				t.Fatal(err)
			}
		}
		file, err := form.CreateFormFile("attachments", "proof.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(file, data); err != nil {
			t.Fatal(err)
		}
		if err := form.Close(); err != nil {
			t.Fatal(err)
		}
		idempotencyKey := ""
		if i == 0 {
			idempotencyKey = uuid.NewString()
		}
		response := postRecording(f.handler, "/api/v1/attestations", idempotencyKey, form.FormDataContentType(), &body, f.sessions[auth.RoleWriter])
		expectRecording(t, response, http.StatusCreated)
		if err := json.Unmarshal(response.Body.Bytes(), &attestations[i]); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(t, f.pool, `UPDATE attestation_types SET jq_rules=ARRAY['false'] WHERE id=$1`, policyID)
	historyID := uuid.NewString()
	mustExec(t, f.pool, `INSERT INTO evidence_attachments
		(id,attestation_id,file_name,file_size,file_hash,storage_path,content_type)
		SELECT $1,id,'historical.txt',0,'hash','retired storage','text/plain'
		FROM attestations WHERE trail_id=$2 AND content_hash IS NULL`, historyID, trail)
	var head string
	if err := f.pool.QueryRow(`SELECT content_hash FROM attestations WHERE id=$1`, attestations[1].ID).Scan(&head); err != nil {
		t.Fatal(err)
	}
	token := offlineChainAnchor(t, head)
	mustExec(t, f.pool, `INSERT INTO trail_anchors (org_id,trail_id,chain_head_hash,tsa_url,timestamp_token)
		VALUES ($1,$2,$3,'https://tsa.example.invalid',$4),($5,$2,$3,'https://tsa.example.invalid',$6)`, org, trail, head, token, f.other["org"], []byte("foreign token"))

	endpoint := "GET /api/v1/trails/" + trail + "/signed-audit-pack"
	auditor := f.sessions[auth.RoleAuditor]
	get := func(t *testing.T, status int) (body, signature []byte) {
		t.Helper()
		rec := serveMutation(t, f.handler, endpoint, "", auditor, status, "")
		if rec.Code != status {
			t.FailNow()
		}
		header := rec.Header().Get(auditpack.SignatureHeader)
		if status == http.StatusOK {
			if rec.Header().Get("Content-Type") != "application/zip" ||
				rec.Header().Get("Content-Length") != strconv.Itoa(rec.Body.Len()) {
				t.Fatalf("unexpected download headers: %v", rec.Header())
			}
			var err error
			signature, err = base64.StdEncoding.DecodeString(header)
			if err != nil || len(signature) == 0 {
				t.Fatalf("decode detached signature: %v", err)
			}
		} else if header != "" || rec.Header().Get("Content-Type") == "application/zip" || bytes.HasPrefix(rec.Body.Bytes(), []byte("PK")) {
			t.Fatalf("failed export returned archive data or headers: %v", rec.Header())
		}
		if leftovers, err := os.ReadDir(stageDir); err != nil || len(leftovers) != 0 {
			t.Fatalf("staging directory after export: %v, %v", leftovers, err)
		}
		return rec.Body.Bytes(), signature
	}

	body, signature := get(t, http.StatusOK)
	assertAuditFixtureSignature(t, body, signature, key)
	stamp, err := timestamp.ParseResponse(token)
	if err != nil || len(stamp.Certificates) != 1 {
		t.Fatalf("parse local timestamp fixture: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(stamp.Certificates[0])
	trust := auditpack.Trust{ArchiveKeys: []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}, TSARoots: roots}
	if got, err := auditpack.Verify(bytes.NewReader(body), signature, trust); err != nil || len(got.Incomplete) != 2 {
		t.Fatalf("offline verification did not preserve historical gaps: %+v, %v", got.Incomplete, err)
	}
	tampered := bytes.Clone(body)
	tampered[len(tampered)-1] ^= 1
	if _, err := auditpack.Verify(bytes.NewReader(tampered), signature, trust); err == nil {
		t.Fatal("modified ZIP bytes verified")
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest auditpack.Manifest
	readAuditFixtureJSON(t, zr, "manifest.json", &manifest)
	if manifest.Version != auditpack.Version || manifest.TrailID != trail || manifest.ChainHead != head ||
		!manifest.Coverage.Valid || manifest.Coverage.EvidenceCount != 2 || manifest.Coverage.UnhashedCount != 1 ||
		len(manifest.Attachments) != 3 || len(manifest.Members) != 7 || len(zr.File) != 8 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	for _, member := range manifest.Members {
		data := readAuditFixtureMember(t, zr, member.Name)
		if int64(len(data)) != member.Size || auditFixtureDigest(data) != member.SHA256 {
			t.Fatalf("manifest member differs from ZIP: %+v", member)
		}
	}
	for _, a := range manifest.Attachments {
		if a.ID == historyID {
			if a.Member != "" || a.SHA256 != "hash" || a.Name != "historical.txt" {
				t.Fatalf("historical metadata or coverage lost: %+v", a)
			}
			continue
		}
		var expected string
		for i, att := range attestations {
			if a.AttestationID == att.ID.String() {
				expected = payload[i]
			}
		}
		if expected == "" || a.Name != "proof.txt" || a.Member != "attachments/"+a.ID ||
			a.SHA256 != auditFixtureDigest([]byte(expected)) || a.Size != int64(len(expected)) ||
			string(readAuditFixtureMember(t, zr, a.Member)) != expected {
			t.Fatalf("bad exact attachment: %+v", a)
		}
	}
	var chain []auditpack.ChainRecord
	readAuditFixtureJSON(t, zr, "chain.json", &chain)
	if len(chain) != 3 || chain[1].ID != attestations[0].ID.String() || chain[2].ID != attestations[1].ID.String() ||
		!strings.Contains(chain[1].Entry.Evidence, policyID.String()) || !strings.Contains(chain[1].Entry.Evidence, ".ok == true") {
		t.Fatalf("unexpected chain or missing historical policy: %+v", chain)
	}
	var anchors []auditpack.Anchor
	readAuditFixtureJSON(t, zr, "anchors.json", &anchors)
	if len(anchors) != 1 || anchors[0].Head != head || !bytes.Equal(anchors[0].Token, token) {
		t.Fatalf("raw anchor mismatch: %d anchors", len(anchors))
	}
	var metadata map[string]any
	readAuditFixtureJSON(t, zr, "trail.json", &metadata)
	if metadata["id"] != trail || metadata["org_id"] != org {
		t.Fatalf("unexpected trail metadata: %v", metadata)
	}
	for name, wanted := range map[string]string{"artifacts.json": "audited-file", "approvals.json": "audit@example.invalid"} {
		data := readAuditFixtureMember(t, zr, name)
		if !bytes.Contains(data, []byte(wanted)) || bytes.Contains(data, []byte("foreign")) {
			t.Fatalf("wrong tenant data in %s: %s", name, data)
		}
	}
	if !bytes.Contains(readAuditFixtureMember(t, zr, "artifacts.json"), []byte("referenced-file")) {
		t.Fatal("same-tenant artifact referenced by an attestation was missing")
	}

	t.Run("key rotation", func(t *testing.T) {
		rotated := writeAuditFixtureKey(t, keyPath)
		after, sig := get(t, http.StatusOK)
		assertAuditFixtureSignature(t, after, sig, rotated)
		assertAuditFixtureSignature(t, body, signature, key)
		if bytes.Equal(signature, sig) {
			t.Fatal("signing key did not rotate")
		}
	})
	t.Run("unavailable key leaves legacy export available", func(t *testing.T) {
		t.Setenv("FIDES_AUDIT_PACK_PRIVATE_KEY_FILE", keyPath+".missing")
		get(t, http.StatusServiceUnavailable)
		legacy := serveMutation(t, f.handler, "GET /api/v1/trails/"+trail+"/audit-package", "", auditor, http.StatusOK, "")
		if legacy.Header().Get(auditpack.SignatureHeader) != "" {
			t.Fatal("legacy export returned a signature")
		}
	})
	t.Run("foreign tenant", func(t *testing.T) {
		foreign := routeSession(t, f.server, f.other["org"], auth.RoleAuditor, time.Hour)
		rec := serveMutation(t, f.handler, endpoint, "", foreign, http.StatusNotFound, "")
		if rec.Header().Get(auditpack.SignatureHeader) != "" {
			t.Fatal("foreign tenant received a signature")
		}
	})

	t.Run("repeatable read", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		tx, err := f.pool.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, `LOCK TABLE artifacts IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		type snapshotResult struct {
			snapshot auditSnapshot
			err      error
		}
		done := make(chan snapshotResult, 1)
		go func() {
			snapshot, err := f.server.readSignedAuditSnapshot(ctx, uuid.MustParse(org), uuid.MustParse(trail))
			done <- snapshotResult{snapshot, err}
		}()

		// The export has read its trail and chain when it reaches this lock.
		for {
			var waiting bool
			if err := f.pool.QueryRowContext(ctx, `SELECT EXISTS (
				SELECT 1 FROM pg_locks WHERE relation = 'artifacts'::regclass
				AND mode = 'AccessShareLock' AND NOT granted)`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		const late = "late-approval@example.invalid"
		if _, err := tx.ExecContext(ctx, `INSERT INTO trail_approvals (org_id,trail_id,approved_by,approver_kind)
			VALUES ($1,$2,$3,'session')`, org, trail, late); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		got := <-done
		if got.err != nil {
			t.Fatal(got.err)
		}
		for _, member := range got.snapshot.members {
			if member.name == "approvals.json" && bytes.Contains(member.data, []byte(late)) {
				t.Fatal("approval committed after the export snapshot was included")
			}
		}
		next, _ := get(t, http.StatusOK)
		nextZIP, err := zip.NewReader(bytes.NewReader(next), int64(len(next)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(readAuditFixtureMember(t, nextZIP, "approvals.json"), []byte(late)) {
			t.Fatal("approval was missing from the next export")
		}
	})

	var uri string
	if err := f.pool.QueryRow(`SELECT storage_path FROM evidence_attachments WHERE attestation_id=$1`, attestations[0].ID).Scan(&uri); err != nil {
		t.Fatal(err)
	}
	for name, forged := range map[string]string{
		"foreign attachment prefix": strings.Replace(uri, org, f.other["org"], 1),
		"foreign storage scheme":    strings.Replace(uri, "local://", "s3://", 1),
	} {
		t.Run(name, func(t *testing.T) {
			mustExec(t, f.pool, `UPDATE evidence_attachments SET storage_path=$1 WHERE attestation_id=$2`, forged, attestations[0].ID)
			t.Cleanup(func() {
				mustExec(t, f.pool, `UPDATE evidence_attachments SET storage_path=$1 WHERE attestation_id=$2`, uri, attestations[0].ID)
			})
			get(t, http.StatusInternalServerError)
		})
	}
	object := filepath.Join(local.BaseDir, strings.TrimPrefix(uri, "local://"))
	for name, value := range map[string]string{
		"wrong size":   payload[0] + "extra",
		"wrong digest": strings.Repeat("x", len(payload[0])),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(object, []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
			get(t, http.StatusInternalServerError)
		})
	}
	t.Run("missing object", func(t *testing.T) {
		if err := os.Remove(object); err != nil {
			t.Fatal(err)
		}
		get(t, http.StatusInternalServerError)
	})
	t.Run("attachment stream error", func(t *testing.T) {
		// Local storage can open the directory but reading from it fails.
		if err := os.Mkdir(object, 0700); err != nil {
			t.Fatal(err)
		}
		get(t, http.StatusInternalServerError)
	})
	t.Run("query failure", func(t *testing.T) {
		mustExec(t, f.pool, `ALTER TABLE trail_approvals RENAME COLUMN org_id TO unavailable_org_id`)
		get(t, http.StatusInternalServerError)
	})
}

func writeAuditFixtureKey(t *testing.T, filename string) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return key
}

func assertAuditFixtureSignature(t *testing.T, body, sig []byte, key ed25519.PrivateKey) {
	t.Helper()
	var detached struct {
		KeyID     string `json:"key_id"`
		Signature []byte `json:"signature"`
	}
	if err := json.Unmarshal(sig, &detached); err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(body)
	if detached.KeyID != auditFixtureDigest(pub) ||
		!ed25519.Verify(pub, append([]byte("fides:audit-pack:v1\x00"), digest[:]...), detached.Signature) {
		t.Fatal("signature does not cover exact delivered archive bytes")
	}
}

func auditFixtureDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readAuditFixtureJSON(t *testing.T, z *zip.Reader, name string, dst any) {
	t.Helper()
	if err := json.Unmarshal(readAuditFixtureMember(t, z, name), dst); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

func readAuditFixtureMember(t *testing.T, z *zip.Reader, name string) []byte {
	t.Helper()
	f, err := z.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
