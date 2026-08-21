package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
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

type createAttestationTypeReq struct {
	OrgID       string   `json:"org_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Schema      string   `json:"schema"`
	JQRules     []string `json:"jq_rules"`
}

func (s *Server) handleCreateAttestationType(w http.ResponseWriter, r *http.Request) {
	var req createAttestationTypeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}

	// Tenant scope comes from the authenticated principal, never the request body (H2/IDOR).
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var err error

	attType := &models.AttestationType{
		ID:          uuid.New(),
		OrgID:       orgID,
		Name:        req.Name,
		Description: req.Description,
		Schema:      req.Schema,
		JQRules:     req.JQRules,
		CreatedAt:   time.Now(),
	}

	query := `INSERT INTO attestation_types (id, org_id, name, description, schema, jq_rules, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err = s.q(r.Context()).ExecContext(r.Context(), query, attType.ID, attType.OrgID, attType.Name, attType.Description, attType.Schema, pq.Array(attType.JQRules), attType.CreatedAt)
	if err != nil {
		internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(attType)
}

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
	contentType := r.Header.Get("Content-Type")

	var req reportAttestationReq
	var fileReaders []io.Reader
	var fileNames []string

	if contentType == "application/json" || contentType == "" {
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

		files := r.MultipartForm.File["attachments"]
		for _, fHeaders := range files {
			f, err := fHeaders.Open()
			if err != nil {
				internalError(w, err)
				return
			}
			defer f.Close()
			fileReaders = append(fileReaders, f)
			fileNames = append(fileNames, fHeaders.Filename)
		}
	}

	// Payload Decryption Step
	isEncrypted := r.FormValue("encrypted") == "true" || r.Header.Get("X-Fides-Encrypted") == "true"
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// trail_id is caller-supplied. This endpoint WRITES compliance evidence, so
	// without this a tenant could attest onto another tenant's trail.
	if !s.requireTrailInOrg(w, r, trailID) {
		return
	}

	// Fetch rules for verification, scoped to the caller's org: attestation_types
	// is org-scoped (UNIQUE(org_id,name)), so an unscoped lookup could apply
	// another tenant's JQ rules for a same-named type (#326).
	orgID, _ := principalOrg(r)
	var rules []string
	queryType := `SELECT jq_rules FROM attestation_types WHERE name = $1 AND org_id = $2 LIMIT 1`
	err = s.q(r.Context()).QueryRowContext(r.Context(), queryType, req.TypeName, orgID).Scan(pq.Array(&rules))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		internalError(w, err)
		return
	}

	// Evaluate JQ rules
	isCompliant := true
	if len(rules) > 0 {
		ok, failedRules, err := s.PolicyEngine.EvaluateAttestation(req.Payload, rules)
		if err != nil {
			internalError(w, err)
			return
		}
		if !ok {
			isCompliant = false
			log.Printf("Compliance check failed for rules: %v", failedRules)
		}
	}

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
		SignedBy:            req.SignedBy,
		Signature:           req.Signature,
		SignatureAlgorithm:  req.SignatureAlgorithm,
		ManifestationReason: req.ManifestationReason,
		CreatedAt:           time.Now(),
	}

	contentHash, prevHash, err := s.attestationChain(r.Context(), attestation.TrailID, attestation.Name, attestation.TypeName, attestation.Payload, attestation.IsCompliant)
	if err != nil {
		internalError(w, err)
		return
	}
	queryInsert := `INSERT INTO attestations (id, trail_id, artifact_sha256, name, type_name, payload, is_compliant, signed_by, signature, signature_algorithm, manifestation_reason, content_hash, prev_hash, created_at)
	                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
	_, err = s.q(r.Context()).ExecContext(r.Context(), queryInsert, attestation.ID, attestation.TrailID, attestation.ArtifactSHA256, attestation.Name, attestation.TypeName, attestation.Payload, attestation.IsCompliant, attestation.SignedBy, attestation.Signature, attestation.SignatureAlgorithm, attestation.ManifestationReason, contentHash, prevHash, attestation.CreatedAt)
	if err != nil {
		internalError(w, err)
		return
	}

	// Emit a compliance.evaluated event so CI/CD commit-status gates can publish
	// the verdict to the trail's commit (opt-in via FIDES_EVENTS_ENABLED).
	orgID, hasOrg := principalOrg(r)
	if os.Getenv("FIDES_EVENTS_ENABLED") == "true" {
		if hasOrg {
			if err := events.Enqueue(r.Context(), s.q(r.Context()), orgID, "compliance.evaluated", map[string]any{
				"trail_id": attestation.TrailID.String(),
				// Both, because they are not the same thing and consumers want
				// different ones. "attestation" is the human label a Slack
				// message or commit status shows. "attestation_type" is what
				// controls.required_types is matched against -- the change gate
				// has always joined on type_name, so anything resolving controls
				// must too. They are equal for almost every attestation on the
				// live estate, which is exactly why the difference goes unnoticed
				// until it does not: "pull-request" is stored with type_name
				// "pull_request".
				"attestation":      attestation.Name,
				"attestation_type": attestation.TypeName,
				"compliant":        attestation.IsCompliant,
			}); err != nil {
				log.Printf("failed to enqueue compliance.evaluated event: %v", err)
			}
		}
	}

	// `fides attest sbom` normalizes the SBOM client-side (see pkg/evidence.
	// ParseSBOM) and uploads it as a "sbom-cyclonedx" attestation (the evidence
	// type the built-in control frameworks require); persist its component list
	// so `fides search components` can answer "which artifacts contain
	// component X". Best-effort: a parse/insert failure here does not fail the
	// attestation itself, since it is already durably recorded. Attestations
	// recorded via the generic `fides attest --type sbom-cyclonedx` path (a raw,
	// non-normalized CycloneDX payload) are also matched here but simply fail
	// this best-effort parse (no "components" field in the expected shape).
	if req.TypeName == "sbom-cyclonedx" && artifactSHA != nil && hasOrg {
		if err := s.persistSBOMComponents(r.Context(), orgID, *artifactSHA, attestation.ID, attestation.Payload); err != nil {
			log.Printf("failed to persist sbom components: %v", err)
		}
	}

	// Vulnerability-scan attestations (trivy/snyk/sarif) carry CVE IDs only as
	// findings[] strings; extract them into artifact_vulnerabilities so the
	// CVE->environment impact query can answer "which environments ship CVE-X".
	// Best-effort, like SBOM components above.
	if vulnScanTypes[req.TypeName] && artifactSHA != nil && hasOrg {
		if err := s.persistVulnerabilities(r.Context(), orgID, *artifactSHA, attestation.ID, req.TypeName, attestation.Payload); err != nil {
			log.Printf("failed to persist vulnerabilities: %v", err)
		}
	}

	// Upload attachments to Object Store and save mapping
	for i, reader := range fileReaders {
		// Use only the base name of the client-supplied filename to prevent
		// path traversal (e.g. "../../etc/passwd") in the storage key.
		safeName := filepath.Base(filepath.Clean("/" + fileNames[i]))
		key := fmt.Sprintf("%s/%s", attestation.ID, safeName)
		bucket := os.Getenv("AWS_S3_BUCKET")
		if bucket == "" {
			bucket = "fides-evidence"
		}
		path, err := s.Storage.Upload(r.Context(), bucket, key, reader, "application/octet-stream")
		if err != nil {
			internalError(w, err)
			return
		}

		attachmentID := uuid.New()
		queryAttach := `INSERT INTO evidence_attachments (id, attestation_id, file_name, file_size, file_hash, storage_path, content_type, created_at)
		                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
		_, err = s.q(r.Context()).ExecContext(r.Context(), queryAttach, attachmentID, attestation.ID, fileNames[i], 0, "hash", path, "application/octet-stream", time.Now())
		if err != nil {
			log.Printf("Failed to record attachment in DB: %v", err)
		}
	}

	// Trigger async LLM Evaluation if provider config exists
	if s.LLM != nil {
		llmOrgID, _ := principalOrg(r)
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
			werr := db.WithOrgScope(ctx, s.DB, llmOrgID.String(), func(tx *sql.Tx) error {
				_, e := tx.ExecContext(ctx, queryAss, assID, attestation.ID, "local", "llama3", "v1", assessment, score, "[]", time.Now())
				return e
			})
			if werr != nil {
				log.Printf("Failed to write LLM assessment to DB: %v", werr)
			}
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(attestation)
}

// resolveAttestationTrailID parses trailIDStr, or — when it is empty — resolves
// the trail from the reported artifact, so `fides attest sbom` can omit
// --trail (every artifact already belongs to exactly one trail).
func (s *Server) resolveAttestationTrailID(ctx context.Context, orgID uuid.UUID, trailIDStr string, artifactSHA *string) (uuid.UUID, error) {
	if trailIDStr != "" {
		id, err := uuid.Parse(trailIDStr)
		if err != nil {
			return uuid.UUID{}, fmt.Errorf("invalid trail_id")
		}
		return id, nil
	}
	if artifactSHA == nil {
		return uuid.UUID{}, fmt.Errorf("trail_id or artifact_sha256 is required")
	}
	var trailID uuid.NullUUID
	// Scoped by org: sha256 is the artifacts PRIMARY KEY, so a digest is global
	// across tenants. Unscoped, a caller could name another tenant's digest and
	// have its trail resolved — and then have an attestation written onto it.
	err := s.q(ctx).QueryRowContext(ctx,
		`SELECT trail_id FROM artifacts WHERE sha256 = $1 AND org_id = $2`, *artifactSHA, orgID).Scan(&trailID)
	if err == sql.ErrNoRows {
		return uuid.UUID{}, fmt.Errorf("artifact %s not found", *artifactSHA)
	}
	if err != nil {
		return uuid.UUID{}, err
	}
	if !trailID.Valid {
		return uuid.UUID{}, fmt.Errorf("artifact %s has no associated trail; provide --trail explicitly", *artifactSHA)
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
		return fmt.Errorf("parse sbom payload: %w", err)
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

	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w, err)
		return
	}
	defer tx.Rollback()

	// Establish the tenant RLS session context on this transaction, mirroring
	// handleImportFramework. handleReportSnapshot begins its transaction on the
	// raw unscoped pool (s.DB), which has no app.current_org GUC set. Without
	// this, the environment_snapshots RLS WITH CHECK (whose subquery reads
	// environments under RLS) sees no visible environments and every insert is
	// rejected with 42501. This is a harmless no-op when FIDES_RLS_ENABLED is
	// false, since RLS enforcement itself is not configured on the tables then.
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
		rows, err := tx.QueryContext(r.Context(), queryAtt, dbTrailID)
		if err != nil {
			internalError(w, err)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var attName string
			var compliant bool
			if err := rows.Scan(&attName, &compliant); err != nil {
				internalError(w, err)
				return
			}
			if !compliant {
				drifts = append(drifts, fmt.Sprintf("service %s running drifted artifact %s (failing control: %s)", a.ServiceName, a.SHA256, attName))
				isCompliant = false
			}
		}
		// A failed iteration must not read as a short result.
		if err := rows.Err(); err != nil {
			internalError(w, err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		internalError(w, err)
		return
	}

	// Emit an integration event for downstream gates/alerts (opt-in via
	// FIDES_EVENTS_ENABLED). Best-effort: the snapshot is already committed, so a
	// failure here must not fail the request.
	if os.Getenv("FIDES_EVENTS_ENABLED") == "true" && (len(shadows) > 0 || len(drifts) > 0) {
		payload := map[string]any{
			"environment_id": envID.String(),
			"snapshot_id":    snapshotID.String(),
			"compliant":      isCompliant,
			"shadows":        shadows,
			"drifts":         drifts,
		}
		if err := events.Enqueue(r.Context(), s.q(r.Context()), orgID, "snapshot.noncompliant", payload); err != nil {
			log.Printf("failed to enqueue snapshot.noncompliant event: %v", err)
		}
	}

	// Emit a snapshot.reported event on every snapshot (CMDB sync consumes this).
	if os.Getenv("FIDES_EVENTS_ENABLED") == "true" && len(services) > 0 {
		if err := events.Enqueue(r.Context(), s.q(r.Context()), orgID, "snapshot.reported", map[string]any{
			"environment": envID.String(),
			"services":    services,
		}); err != nil {
			log.Printf("failed to enqueue snapshot.reported event: %v", err)
		}
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
