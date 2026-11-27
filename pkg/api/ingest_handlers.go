package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"fides/pkg/crypto"
	"fides/pkg/db"
	"fides/pkg/events"
	"fides/pkg/evidence"
	"fides/pkg/models"
)

// Evidence ingestion: attestations and runtime snapshots.
//
// This is the hot path -- what CI posts on every build, and what the reporters
// post from every cluster. handleReportSnapshot is also where a shadow change
// is first detected, by comparing running digests against registered artifacts.

type reportAttestationReq struct {
	TrailID             string `json:"trail_id"`
	ArtifactSHA256      string `json:"artifact_sha256"`
	Name                string `json:"name"` // unit-tests, sbom, snyk-scan
	TypeName            string `json:"type_name"`
	Payload             string `json:"payload"` // JSON string
	SignedBy            string `json:"signed_by"`
	Signature           string `json:"signature"`
	SignatureAlgorithm  string `json:"signature_algorithm"`
	ManifestationReason string `json:"manifestation_reason"`
}

func (s *Server) handleReportAttestation(w http.ResponseWriter, r *http.Request) {
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))

	var req reportAttestationReq
	var files []*multipart.FileHeader

	if contentType == "application/json" || r.Header.Get("Content-Type") == "" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, err)
			return
		}
	} else {
		// #nosec G120 -- bounded to 32MB in-memory; total request body is capped by the limitBody middleware
		err := r.ParseMultipartForm(32 << 20)
		if err != nil {
			badRequest(w, err)
			return
		}

		req.TrailID = r.FormValue("trail_id")
		req.ArtifactSHA256 = r.FormValue("artifact_sha256")
		req.Name = r.FormValue("name")
		req.TypeName = r.FormValue("type_name")
		req.Payload = r.FormValue("payload")
		req.SignedBy = r.FormValue("signed_by")
		req.Signature = r.FormValue("signature")
		req.SignatureAlgorithm = r.FormValue("signature_algorithm")
		req.ManifestationReason = r.FormValue("manifestation_reason")

		defer func() { _ = r.MultipartForm.RemoveAll() }()
		files = r.MultipartForm.File["attachments"]
	}

	isEncrypted := r.FormValue("encrypted") == "true" || r.Header.Get("X-Fides-Encrypted") == "true"

	var artifactSHA *string
	if req.ArtifactSHA256 != "" {
		artifactSHA = &req.ArtifactSHA256
	}

	// trail_id is normally required, but `fides attest sbom` may omit --trail
	// and rely on the artifact's own trail (every artifact is reported against
	// exactly one trail via `fides artifact report`).
	callerOrg, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	trailID, err := s.resolveAttestationTrailID(r.Context(), callerOrg, req.TrailID, artifactSHA)
	if err != nil {
		var targetErr attestationTargetError
		if errors.As(err, &targetErr) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			internalError(w, err)
		}
		return
	}
	// trail_id is caller-supplied. This endpoint WRITES compliance evidence, so
	// without this a tenant could attest onto another tenant's trail.
	if !s.requireTrailInOrg(w, r, trailID) {
		return
	}

	if len(r.Header.Values("Idempotency-Key")) != 0 && req.TrailID != "" && artifactSHA != nil {
		var owned bool
		err := s.q(r.Context()).QueryRowContext(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM artifacts WHERE sha256 = $1 AND org_id = $2)`, *artifactSHA, callerOrg).Scan(&owned)
		if err != nil {
			internalError(w, err)
			return
		}
		if !owned {
			http.Error(w, "artifact not found", http.StatusNotFound)
			return
		}
	}

	type attachmentDigest struct {
		Name string
		Size int64
		Hash string
	}
	digests := make([]attachmentDigest, 0, len(files))
	readers := make([]multipart.File, 0, len(files))
	for _, header := range files {
		file, err := header.Open()
		if err != nil {
			internalError(w, err)
			return
		}
		defer file.Close()
		hash := sha256.New()
		size, err := io.Copy(hash, file)
		if err != nil {
			internalError(w, err)
			return
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			internalError(w, err)
			return
		}
		readers = append(readers, file)
		digests = append(digests, attachmentDigest{header.Filename, size, hex.EncodeToString(hash.Sum(nil))})
	}
	op, r := s.beginRecording(w, r, struct {
		Request     reportAttestationReq
		Encrypted   bool
		Attachments []attachmentDigest
	}{req, isEncrypted, digests}, len(files) != 0)
	if op == nil {
		return
	}
	defer op.rollback()

	if isEncrypted {
		encryptionKey := os.Getenv("FIDES_ENCRYPTION_KEY")
		if encryptionKey == "" {
			http.Error(w, "server error: decryption key not configured on server", http.StatusInternalServerError)
			return
		}
		key, err := crypto.DeriveKey(encryptionKey)
		if err != nil {
			http.Error(w, "server error: invalid decryption key configured", http.StatusInternalServerError)
			return
		}
		decrypted, err := crypto.Decrypt(req.Payload, key)
		if err != nil {
			http.Error(w, "decryption failure: payload could not be decrypted", http.StatusBadRequest)
			return
		}
		req.Payload = string(decrypted)
	}

	if !json.Valid([]byte(req.Payload)) {
		http.Error(w, "invalid attestation payload JSON", http.StatusBadRequest)
		return
	}

	orgID := callerOrg
	check, err := s.evaluateAttestationTypeCompliance(r.Context(), orgID, req.TypeName, req.Payload)
	if err != nil {
		internalError(w, err)
		return
	}
	isCompliant := check.compliant

	// code.authorship: an AI-authored change must carry a human reviewer to be
	// compliant, so a control requiring code.authorship holds the change gate on
	// unreviewed agent-generated code. Applied only when no registered JQ rule
	// already marked it non-compliant (registered rules take precedence).
	if req.TypeName == "code.authorship" && isCompliant {
		var a evidence.Authorship
		if err := json.Unmarshal([]byte(req.Payload), &a); err != nil {
			// Fail closed: an unparseable authorship payload cannot be trusted to
			// pass the gate.
			isCompliant = false
			log.Printf("code.authorship payload unparseable, marking non-compliant: %v", err)
		} else {
			isCompliant = a.Compliant()
		}
	}

	attestation := &models.Attestation{
		ID:                  uuid.New(),
		TrailID:             trailID,
		ArtifactSHA256:      artifactSHA,
		Name:                req.Name,
		TypeName:            req.TypeName,
		Payload:             req.Payload,
		IsCompliant:         isCompliant,
		ValidationErrors:    check.reasons,
		SignedBy:            req.SignedBy,
		Signature:           req.Signature,
		SignatureAlgorithm:  req.SignatureAlgorithm,
		ManifestationReason: req.ManifestationReason,
	}

	if err := s.appendAttestation(r.Context(), attestation, &orgID); err != nil {
		internalError(w, err)
		return
	}

	// Index the findings alongside the evidence when this request owns a transaction.
	if req.TypeName == "sbom-cyclonedx" && artifactSHA != nil {
		if err := s.persistSBOMComponents(r.Context(), orgID, *artifactSHA, attestation.ID, attestation.Payload); err != nil {
			if op.tx != nil {
				internalError(w, err)
				return
			}
			log.Printf("failed to persist sbom components: %v", err)
		}
	}
	if vulnScanTypes[req.TypeName] && artifactSHA != nil {
		if err := s.persistVulnerabilities(r.Context(), orgID, *artifactSHA, attestation.ID, req.TypeName, attestation.Payload); err != nil {
			if op.tx != nil {
				internalError(w, err)
				return
			}
			log.Printf("failed to persist vulnerabilities: %v", err)
		}
	}

	bucket := os.Getenv("AWS_S3_BUCKET")
	if bucket == "" {
		bucket = "fides-evidence"
	}
	prefix := attestation.ID.String()
	if op.keyed {
		// A rolled-back upload can be retried at the same key. A different
		// payload cannot overwrite any object belonging to the earlier attempt.
		prefix = fmt.Sprintf("recordings/%s/%s/%x", orgID, op.operationID, op.fingerprint)
	}
	for i, file := range readers {
		if s.Storage == nil {
			internalError(w, errors.New("attachment storage is not configured"))
			return
		}
		digest := digests[i]
		key := fmt.Sprintf("%s/%d-%s", prefix, i, digest.Hash)
		const contentType = "application/octet-stream"
		path, err := s.Storage.Upload(r.Context(), bucket, key, file, contentType)
		if err != nil {
			internalError(w, err)
			return
		}

		const query = `INSERT INTO evidence_attachments (id, attestation_id, file_name, file_size, file_hash, storage_path, content_type, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
		if _, err := s.q(r.Context()).ExecContext(r.Context(), query, uuid.New(), attestation.ID, digest.Name,
			digest.Size, digest.Hash, path, contentType, time.Now()); err != nil {
			internalError(w, err)
			return
		}
	}
	if !op.created(w, r.Context(), attestation) {
		return
	}

	// Trigger async LLM Evaluation if provider config exists
	if s.LLM != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
			defer cancel()
			assessment, score, err := s.LLM.EvaluateAttestation(ctx, attestation.Name, attestation.TypeName, attestation.Payload)
			if err != nil {
				log.Printf("LLM Audit error: %v", err)
				return
			}

			// Save LLM assessment findings. This runs on a detached background
			// context, so scope the write to the tenant (app.current_org) via a
			// transaction, otherwise RLS rejects the insert.
			assID := uuid.New()
			queryAss := `INSERT INTO llm_assessments (id, attestation_id, model_provider, model_name, prompt_template_version, assessment_raw, compliance_score, findings, created_at)
			             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
			werr := db.WithOrgScope(ctx, s.DB, orgID.String(), func(tx *sql.Tx) error {
				_, e := tx.ExecContext(ctx, queryAss, assID, attestation.ID, "local", "llama3", "v1", assessment, score, "[]", time.Now())
				return e
			})
			if werr != nil {
				log.Printf("Failed to write LLM assessment to DB: %v", werr)
			}
		}()
	}
}

type attestationTargetError struct{ error }

// resolveAttestationTrailID parses trailIDStr, or — when it is empty — resolves
// the trail from the reported artifact, so `fides attest sbom` can omit
// --trail (every artifact already belongs to exactly one trail).
func (s *Server) resolveAttestationTrailID(ctx context.Context, orgID uuid.UUID, trailIDStr string, artifactSHA *string) (uuid.UUID, error) {
	if trailIDStr != "" {
		id, err := uuid.Parse(trailIDStr)
		if err != nil {
			return uuid.UUID{}, attestationTargetError{errors.New("invalid trail_id")}
		}
		return id, nil
	}
	if artifactSHA == nil {
		return uuid.UUID{}, attestationTargetError{errors.New("trail_id or artifact_sha256 is required")}
	}
	var trailID uuid.NullUUID
	// Scoped by org: sha256 is the artifacts PRIMARY KEY, so a digest is global
	// across tenants. Unscoped, a caller could name another tenant's digest and
	// have its trail resolved — and then have an attestation written onto it.
	err := s.q(ctx).QueryRowContext(ctx,
		`SELECT trail_id FROM artifacts WHERE sha256 = $1 AND org_id = $2`, *artifactSHA, orgID).Scan(&trailID)
	if err == sql.ErrNoRows {
		return uuid.UUID{}, attestationTargetError{fmt.Errorf("artifact %s not found", *artifactSHA)}
	}
	if err != nil {
		return uuid.UUID{}, err
	}
	if !trailID.Valid {
		return uuid.UUID{}, attestationTargetError{fmt.Errorf("artifact %s has no associated trail; provide --trail explicitly", *artifactSHA)}
	}
	return trailID.UUID, nil
}

// persistSBOMComponents parses the "components" array out of a normalized SBOM
// attestation payload (see pkg/evidence.ParseSBOM) and stores each component
// linked to the artifact, powering `fides search components`.
func (s *Server) persistSBOMComponents(ctx context.Context, orgID uuid.UUID, artifactSHA string, attestationID uuid.UUID, payload string) error {
	var parsed struct {
		Components []struct {
			Name     string   `json:"name"`
			Version  string   `json:"version"`
			PURL     string   `json:"purl"`
			Licenses []string `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(payload), &parsed); err != nil {
		// Raw CycloneDX attestations are valid evidence even when they cannot be indexed.
		log.Printf("parse sbom payload: %v", err)
		return nil
	}
	for _, c := range parsed.Components {
		if c.Name == "" {
			continue
		}
		licenses := c.Licenses
		if licenses == nil {
			licenses = []string{} // avoid pq.Array(nil) -> SQL NULL against the NOT NULL column
		}
		_, err := s.q(ctx).ExecContext(ctx,
			`INSERT INTO sbom_components (id, org_id, artifact_sha256, attestation_id, name, version, purl, licenses, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			uuid.New(), orgID, artifactSHA, attestationID, c.Name, c.Version, c.PURL, pq.Array(licenses), time.Now())
		if err != nil {
			return fmt.Errorf("insert sbom component %q: %w", c.Name, err)
		}
	}
	return nil
}

type reportSnapshotReq struct {
	EnvironmentID string `json:"environment_id"`
	Artifacts     []struct {
		SHA256      string `json:"sha256"`
		ServiceName string `json:"service_name"`
	} `json:"artifacts"`
}

type snapshotReportResponse struct {
	SnapshotID uuid.UUID `json:"snapshot_id"`
	Compliant  bool      `json:"compliant"`
	Drifts     []string  `json:"drifts"`
	Shadows    []string  `json:"shadow_changes"`
}

func (s *Server) handleReportSnapshot(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req reportSnapshotReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	envID, err := uuid.Parse(req.EnvironmentID)
	if err != nil {
		http.Error(w, "invalid environment_id", http.StatusBadRequest)
		return
	}
	if !s.requireEnvInOrg(w, r, envID) {
		return
	}

	tx, err := db.BeginTx(r.Context(), s.DB, nil)
	if err != nil {
		internalError(w, err)
		return
	}
	defer tx.Rollback()

	// Keep the tenant scope transaction-local even without request pinning.
	if _, err := tx.ExecContext(r.Context(), "SELECT set_config('app.current_org', $1, true)", orgID.String()); err != nil {
		internalError(w, err)
		return
	}

	snapshotID := uuid.New()
	querySnap := `INSERT INTO environment_snapshots (id, environment_id, created_at) VALUES ($1, $2, $3)`
	_, err = tx.ExecContext(r.Context(), querySnap, snapshotID, envID, time.Now())
	if err != nil {
		internalError(w, err)
		return
	}

	var drifts []string
	var shadows []string
	var services []map[string]any // running services, for the CMDB sync event
	isCompliant := true

	for _, a := range req.Artifacts {
		// Verify artifact provenance
		var dbSHA, dbTrailID string
		// Scoped by org. A digest is globally unique (artifacts PK), so an
		// unscoped lookup let one tenant inherit another's provenance: reporting
		// a digest someone else registered returned "compliant, no shadows" for
		// an image this org never built. Out of scope now means unregistered,
		// which falls through to the allowlist check below — correct, because an
		// image you neither built nor approved IS unexplained.
		queryArt := `SELECT sha256, trail_id FROM artifacts WHERE sha256 = $1 AND org_id = $2 LIMIT 1`
		err := tx.QueryRowContext(r.Context(), queryArt, a.SHA256, orgID).Scan(&dbSHA, &dbTrailID)

		if errors.Is(err, sql.ErrNoRows) {
			// Not registered — but it may be an APPROVED third-party image.
			// environment_allowlist records an explicit, attributed exception
			// (approved_by + reason), which is exactly the compliance concept
			// of an accepted risk. Until this check existed, the allowlist had
			// no effect on the verdict at all: approving an image left it
			// counted as a shadow change and the environment non-compliant
			// forever, so the only way to a green verdict was to have no
			// third-party images at all. Every real environment has some —
			// this one runs postgres.
			var approved bool
			if aerr := tx.QueryRowContext(r.Context(),
				`SELECT EXISTS(SELECT 1 FROM environment_allowlist WHERE environment_id = $1 AND artifact_sha256 = $2)`,
				envID, a.SHA256).Scan(&approved); aerr != nil {
				internalError(w, aerr)
				return
			}
			if approved {
				// Recorded as running and approved. Deliberately NOT added to
				// shadows: an approved image is not an unexplained one, and a
				// list that reports it as such is the noise this replaced.
				services = append(services, map[string]any{"service": a.ServiceName, "digest": a.SHA256, "registered": false, "approved": true})
				saID := uuid.New()
				// A dropped insert here loses a running artifact from the
				// snapshot with nothing to show for it, so the inventory reads
				// complete while being short.
				if _, err := tx.ExecContext(r.Context(),
					`INSERT INTO snapshot_artifacts (id, snapshot_id, artifact_sha256, service_name, runtime_digest, started_at)
					 VALUES ($1, $2, NULL, $3, $4, $5)`,
					saID, snapshotID, a.ServiceName, a.SHA256, time.Now()); err != nil {
					internalError(w, err)
					return
				}
				continue
			}

			// Shadow deployment: digest is running but not registered in database.
			//
			// Two cases wear the same face here, and #432 is about telling them
			// apart: a wholly unknown image, and a routine patch of an image
			// this environment already approved. Both stay non-compliant -- the
			// verdict is unchanged and still fails closed -- but an operator who
			// cannot distinguish them learns to approve digests without looking.
			priorApproval := serviceHasPriorApproval(r.Context(), tx, envID, a.ServiceName)
			shadows = append(shadows, shadowMessage(a.ServiceName, a.SHA256, priorApproval))
			services = append(services, map[string]any{
				"service": a.ServiceName, "digest": a.SHA256, "registered": false,
				"prior_approval": priorApproval,
			})
			isCompliant = false

			// Insert runtime record anyway
			saID := uuid.New()
			querySA := `INSERT INTO snapshot_artifacts (id, snapshot_id, artifact_sha256, service_name, runtime_digest, started_at)
			            VALUES ($1, $2, NULL, $3, $4, $5)`
			// Losing this insert would erase the shadow change that was just
			// detected -- the verdict says non-compliant, the record shows
			// nothing.
			if _, err := tx.ExecContext(r.Context(), querySA, saID, snapshotID, a.ServiceName, a.SHA256, time.Now()); err != nil {
				internalError(w, err)
				return
			}
			continue
		} else if err != nil {
			internalError(w, err)
			return
		}

		services = append(services, map[string]any{"service": a.ServiceName, "digest": a.SHA256, "registered": true})

		// Insert valid trace record
		saID := uuid.New()
		querySA := `INSERT INTO snapshot_artifacts (id, snapshot_id, artifact_sha256, service_name, runtime_digest, started_at)
		            VALUES ($1, $2, $3, $4, $5, $6)`
		_, err = tx.ExecContext(r.Context(), querySA, saID, snapshotID, dbSHA, a.ServiceName, a.SHA256, time.Now())
		if err != nil {
			internalError(w, err)
			return
		}

		// Check for drift (failing compliance controls in build trail)
		queryAtt := `SELECT name, is_compliant FROM attestations WHERE trail_id = $1`
		if err := func() error {
			rows, err := tx.QueryContext(r.Context(), queryAtt, dbTrailID)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var attName string
				var compliant bool
				if err := rows.Scan(&attName, &compliant); err != nil {
					return err
				}
				if !compliant {
					drifts = append(drifts, fmt.Sprintf("service %s running drifted artifact %s (failing control: %s)", a.ServiceName, a.SHA256, attName))
					isCompliant = false
				}
			}
			return rows.Err()
		}(); err != nil {
			internalError(w, err)
			return
		}
	}

	// Emit an integration event for downstream gates/alerts (opt-in via
	// FIDES_EVENTS_ENABLED), atomically with the snapshot.
	if os.Getenv("FIDES_EVENTS_ENABLED") == "true" && (len(shadows) > 0 || len(drifts) > 0) {
		payload := map[string]any{
			"environment_id": envID.String(),
			"snapshot_id":    snapshotID.String(),
			"compliant":      isCompliant,
			"shadows":        shadows,
			"drifts":         drifts,
		}
		if err := events.Enqueue(r.Context(), tx, orgID, "snapshot.noncompliant", payload); err != nil {
			internalError(w, err)
			return
		}
	}

	// Emit snapshot.reported when there is a service inventory for CMDB sync.
	if os.Getenv("FIDES_EVENTS_ENABLED") == "true" && len(services) > 0 {
		if err := events.Enqueue(r.Context(), tx, orgID, "snapshot.reported", map[string]any{
			"environment": envID.String(),
			"services":    services,
		}); err != nil {
			internalError(w, err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(snapshotReportResponse{
		SnapshotID: snapshotID,
		Compliant:  isCompliant,
		Drifts:     drifts,
		Shadows:    shadows,
	})
}
