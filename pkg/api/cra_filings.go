package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"fides/pkg/models"

	"github.com/google/uuid"
)

type craExport struct {
	ID            uuid.UUID       `json:"id"`
	Stage         string          `json:"stage"`
	Revision      int64           `json:"revision"`
	Version       int             `json:"version"`
	Payload       string          `json:"payload"`
	PayloadSHA256 string          `json:"payload_sha256"`
	CreatedAt     time.Time       `json:"created_at"`
	CreatedBy     json.RawMessage `json:"created_by"`
}

type craSubmission struct {
	ID                uuid.UUID       `json:"id"`
	CaseID            uuid.UUID       `json:"case_id"`
	ExportID          uuid.UUID       `json:"export_id"`
	Stage             string          `json:"stage"`
	DeadlineRevision  int64           `json:"deadline_revision"`
	PayloadSHA256     string          `json:"payload_sha256"`
	WorksheetSHA256   string          `json:"worksheet_sha256"`
	SubmittedAt       time.Time       `json:"submitted_at"`
	ExternalReference string          `json:"external_reference"`
	RecordedAt        time.Time       `json:"recorded_at"`
	RecordedBy        json.RawMessage `json:"recorded_by"`
}

const craWorksheetVersion = 1

func craWorksheetFields(kind, stage string) (string, []string) {
	paragraph := "2"
	if kind == "severe-incident" {
		paragraph = "4"
	}
	switch stage {
	case craEarlyWarning:
		fields := []string{"manufacturer", "product", "affected_versions", "member_states", "summary"}
		if kind == "severe-incident" {
			fields = append(fields, "suspected_unlawful_or_malicious_acts")
		}
		return "14(" + paragraph + ")(a)", fields
	case craNotification:
		fields := []string{"manufacturer", "product", "affected_versions", "nature", "measures_taken", "user_mitigation", "sensitivity"}
		if kind == "vulnerability" {
			fields = append(fields, "general_nature_of_exploit")
		} else {
			fields = append(fields, "initial_assessment")
		}
		return "14(" + paragraph + ")(b)", fields
	case craFinal:
		fields := []string{"description", "severity", "impact"}
		if kind == "vulnerability" {
			fields = append(fields, "malicious_actor", "security_update_or_corrective_measures")
		} else {
			fields = append(fields, "threat_or_root_cause", "applied_and_ongoing_mitigation")
		}
		return "14(" + paragraph + ")(c)", fields
	case craIntermediate:
		return "14(6)", []string{"status_update"}
	default:
		return "", nil
	}
}

func exportCRACase(c *craTx, r *http.Request) (any, error) {
	var req struct {
		Stage  string                     `json:"stage"`
		Fields map[string]json.RawMessage `json:"fields"`
	}
	if err := readCRARequest(r, &req); err != nil {
		return nil, err
	}
	article, fields := craWorksheetFields(c.Kind, req.Stage)
	if article == "" {
		return nil, craError{http.StatusBadRequest, "invalid reporting stage"}
	}
	d, err := c.deadline(req.Stage)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, craError{http.StatusConflict, "no intermediate report has been requested"}
	}
	if err != nil {
		return nil, err
	}
	if d.satisfiedAt != nil {
		return nil, craError{http.StatusConflict, "stage already satisfied"}
	}
	form := make(map[string]json.RawMessage, len(fields))
	for _, key := range fields {
		form[key] = nil
	}
	for key, value := range req.Fields {
		form[key] = value
	}
	links, err := c.links()
	if err != nil {
		return nil, err
	}
	worksheet := map[string]any{
		"format": "fides-cra-manual-filing-worksheet", "version": craWorksheetVersion,
		"article": article, "stage": req.Stage, "deadline_revision": d.revision, "due_at": d.dueAt,
		"case_id": c.ID, "kind": c.Kind, "title": c.Title, "cve": c.CVE,
		"awareness_at": c.AwarenessAt, "measure_available_at": c.MeasureAvailableAt,
		"evidence_links": links, "fields": form,
	}
	if req.Stage == craIntermediate {
		var request craIntermediateRequest
		request.DueAt = d.dueAt
		if err := c.tx.QueryRowContext(c.ctx, `SELECT requested_at, reference FROM cra_case_intermediate_requests
			WHERE org_id = $1 AND case_id = $2 AND revision = $3`,
			c.p.OrgID, c.ID, d.revision).Scan(&request.RequestedAt, &request.Reference); err != nil {
			return nil, err
		}
		worksheet["intermediate_request"] = request
	}
	payload, err := json.Marshal(worksheet)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(payload)
	out := craExport{
		ID: uuid.New(), Stage: req.Stage, Revision: d.revision, Version: craWorksheetVersion,
		Payload: string(payload), PayloadSHA256: hex.EncodeToString(sum[:]),
		CreatedAt: c.now, CreatedBy: json.RawMessage(c.actor),
	}
	if _, err := c.tx.ExecContext(c.ctx, `INSERT INTO cra_case_exports
		(id, org_id, case_id, stage, revision, version, payload, payload_sha256, created_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, out.ID, c.p.OrgID, c.ID, out.Stage, out.Revision,
		out.Version, out.Payload, out.PayloadSHA256, out.CreatedAt, c.actor); err != nil {
		return nil, err
	}
	c.status = http.StatusCreated
	return out, nil
}

func (s *Server) submitCRACase(c *craTx, r *http.Request) (any, error) {
	var req struct {
		ExportID          uuid.UUID `json:"export_id"`
		PayloadSHA256     string    `json:"payload_sha256"`
		WorksheetSHA256   string    `json:"worksheet_sha256"`
		Operator          string    `json:"operator"`
		SubmittedAt       time.Time `json:"submitted_at"`
		ExternalReference string    `json:"external_reference"`
	}
	if err := readCRARequest(r, &req); err != nil {
		return nil, err
	}
	req.ExternalReference = strings.TrimSpace(req.ExternalReference)
	req.Operator = strings.TrimSpace(req.Operator)
	digest, err := hex.DecodeString(req.PayloadSHA256)
	worksheetDigest, worksheetErr := hex.DecodeString(req.WorksheetSHA256)
	if req.ExportID == uuid.Nil || len(digest) != sha256.Size || err != nil ||
		len(worksheetDigest) != sha256.Size || worksheetErr != nil ||
		req.ExternalReference == "" || !c.validPast(req.SubmittedAt) {
		return nil, craError{http.StatusBadRequest, "export_id, worksheet_sha256, payload_sha256, submitted_at and external_reference are required"}
	}
	if c.p.UserID == uuid.Nil && req.Operator == "" {
		return nil, craError{http.StatusBadRequest, "operator is required when using a service credential"}
	}
	req.SubmittedAt = craTimestamp(req.SubmittedAt)
	submittedDigest := hex.EncodeToString(digest)
	out := craSubmission{CaseID: c.ID, ExportID: req.ExportID}
	err = c.tx.QueryRowContext(c.ctx, `SELECT stage, revision, payload_sha256 FROM cra_case_exports
		WHERE org_id = $1 AND case_id = $2 AND id = $3`, c.p.OrgID, c.ID, req.ExportID).
		Scan(&out.Stage, &out.DeadlineRevision, &out.WorksheetSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, craError{http.StatusNotFound, "export not found in this case"}
	}
	if err != nil {
		return nil, err
	}
	if out.WorksheetSHA256 != hex.EncodeToString(worksheetDigest) {
		return nil, craError{http.StatusConflict, "worksheet digest does not match the export"}
	}
	err = c.tx.QueryRowContext(c.ctx, `SELECT id, submitted_at, external_reference, recorded_at, recorded_by, payload_sha256
		FROM cra_case_submissions WHERE org_id = $1 AND case_id = $2 AND export_id = $3`, c.p.OrgID, c.ID, req.ExportID).
		Scan(&out.ID, &out.SubmittedAt, &out.ExternalReference, &out.RecordedAt, &out.RecordedBy, &out.PayloadSHA256)
	if err == nil {
		if !out.SubmittedAt.Equal(req.SubmittedAt) || out.ExternalReference != req.ExternalReference || out.PayloadSHA256 != submittedDigest {
			return nil, craError{http.StatusConflict, "submission already recorded with different details"}
		}
		return out, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if req.SubmittedAt.Before(c.AwarenessAt) {
		return nil, craError{http.StatusBadRequest, "submitted_at cannot precede awareness"}
	}
	d, err := c.deadline(out.Stage)
	if err != nil {
		return nil, err
	}
	if d.satisfiedAt != nil || out.DeadlineRevision != d.revision {
		return nil, craError{http.StatusConflict, "stage already satisfied or worksheet deadline superseded"}
	}
	if out.Stage == craIntermediate {
		var requested time.Time
		if err := c.tx.QueryRowContext(c.ctx, `SELECT requested_at FROM cra_case_intermediate_requests
			WHERE org_id = $1 AND case_id = $2 AND revision = $3`, c.p.OrgID, c.ID, out.DeadlineRevision).Scan(&requested); err != nil {
			return nil, err
		}
		if req.SubmittedAt.Before(requested) {
			return nil, craError{http.StatusBadRequest, "submitted_at cannot precede the intermediate request"}
		}
	}
	out.ID, out.SubmittedAt, out.ExternalReference = uuid.New(), req.SubmittedAt, req.ExternalReference
	out.PayloadSHA256 = submittedDigest
	out.RecordedAt, out.RecordedBy = c.now, json.RawMessage(c.actor)
	if c.p.UserID == uuid.Nil {
		out.RecordedBy, err = json.Marshal(map[string]string{"kind": c.p.Kind, "declared_operator": req.Operator})
		if err != nil {
			return nil, err
		}
	}
	if _, err := c.tx.ExecContext(c.ctx, `INSERT INTO cra_case_submissions
		(id, org_id, case_id, export_id, submitted_at, external_reference, recorded_at, recorded_by, payload_sha256)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, out.ID, c.p.OrgID, c.ID, out.ExportID, out.SubmittedAt,
		out.ExternalReference, out.RecordedAt, string(out.RecordedBy), out.PayloadSHA256); err != nil {
		return nil, err
	}
	if err := s.appendCRAConfirmation(c, out); err != nil {
		return nil, err
	}
	if err := c.satisfyDeadline(out.Stage, out.SubmittedAt); err != nil {
		return nil, err
	}
	if err := c.refreshDeadlines(); err != nil {
		return nil, err
	}
	c.status = http.StatusCreated
	return out, nil
}

func (s *Server) appendCRAConfirmation(c *craTx, submission craSubmission) error {
	links, err := c.links()
	if err != nil {
		return err
	}
	if len(links) == 0 {
		return nil
	}
	// The chain receives filing evidence without the worksheet's incident details.
	payload, err := json.Marshal(submission)
	if err != nil {
		return err
	}
	const evidenceType = "cra.submission"
	check, err := s.evaluateAttestationTypeCompliance(c.ctx, c.p.OrgID, evidenceType, string(payload))
	if err != nil {
		return err
	}
	seen := make(map[uuid.UUID]bool)
	// links() orders by trail ID so concurrent cases acquire chain locks consistently.
	for _, link := range links {
		if seen[link.TrailID] {
			continue
		}
		var owned uuid.UUID
		err := c.tx.QueryRowContext(c.ctx, `SELECT t.id FROM trails t JOIN flows f ON f.id = t.flow_id
			WHERE f.org_id = $1 AND t.id = $2 FOR SHARE OF t, f`, c.p.OrgID, link.TrailID).Scan(&owned)
		if errors.Is(err, sql.ErrNoRows) {
			return craError{http.StatusConflict, "linked trail is no longer available to the tenant"}
		}
		if err != nil {
			return err
		}
		if err := s.appendAttestation(c.ctx, &models.Attestation{
			ID: uuid.New(), TrailID: owned, Name: "CRA submission", TypeName: evidenceType,
			Payload: string(payload), IsCompliant: check.compliant, ValidationErrors: check.reasons,
		}, nil, attestationEvidence{}); err != nil {
			return err
		}
		seen[link.TrailID] = true
	}
	return nil
}
