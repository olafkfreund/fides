package api

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// cveRe matches CVE identifiers (e.g. CVE-2021-44228) anywhere in a string.
var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// vulnScanTypes are the attestation type_names whose payloads carry CVE findings.
var vulnScanTypes = map[string]bool{"trivy": true, "snyk": true, "sarif": true}

// persistVulnerabilities extracts CVE IDs from a vulnerability-scan attestation
// payload (trivy/snyk/sarif, see pkg/evidence) and stores them linked to the
// artifact, powering the CVE->environment impact query. CVEs otherwise live
// only as findings[] strings in the payload. Best-effort, like SBOM components:
// a parse/insert failure does not fail the already-recorded attestation.
func (s *Server) persistVulnerabilities(ctx context.Context, orgID uuid.UUID, artifactSHA string, attestationID uuid.UUID, source, payload string) error {
	var parsed struct {
		Findings []string `json:"findings"`
	}
	if err := json.Unmarshal([]byte(payload), &parsed); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, f := range parsed.Findings {
		cve := cveRe.FindString(f)
		if cve == "" || seen[cve] {
			continue
		}
		seen[cve] = true
		// Severity is the leading token before the first ':' (e.g. "CRITICAL: CVE-...").
		severity := ""
		if i := strings.IndexByte(f, ':'); i > 0 && i <= 12 {
			severity = strings.ToUpper(strings.TrimSpace(f[:i]))
		}
		if _, err := s.q(ctx).ExecContext(ctx,
			`INSERT INTO artifact_vulnerabilities (id, org_id, artifact_sha256, attestation_id, cve_id, severity, source, created_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			 ON CONFLICT (artifact_sha256, cve_id, attestation_id) DO NOTHING`,
			uuid.New(), orgID, artifactSHA, attestationID, cve, severity, source, time.Now()); err != nil {
			return err
		}
	}
	return nil
}

// handleRecordVEX stores a VEX statement. A status="not_affected" statement
// suppresses its CVE from the impact query. Admin-scoped.
func (s *Server) handleRecordVEX(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		CVE           string `json:"cve"`
		Product       string `json:"product"`
		Status        string `json:"status"`
		Justification string `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	req.CVE = strings.TrimSpace(req.CVE)
	req.Status = strings.TrimSpace(req.Status)
	if req.CVE == "" || req.Status == "" {
		http.Error(w, "cve and status are required", http.StatusBadRequest)
		return
	}
	switch req.Status {
	case "not_affected", "affected", "fixed", "under_investigation":
	default:
		http.Error(w, "status must be one of: not_affected, affected, fixed, under_investigation", http.StatusBadRequest)
		return
	}
	id := uuid.New()
	if _, err := s.q(r.Context()).ExecContext(r.Context(),
		`INSERT INTO vex_statements (id, org_id, cve_id, product, status, justification, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, p.OrgID, req.CVE, req.Product, req.Status, req.Justification, time.Now()); err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"id": id, "cve": req.CVE, "status": req.Status})
}

// handleImpact answers "which artifacts and running environments are affected by
// CVE-X?", applying VEX not_affected suppression so the result reflects
// exploitable exposure rather than raw scanner output.
// GET /api/v1/impact?cve=CVE-2021-44228
func (s *Server) handleImpact(w http.ResponseWriter, r *http.Request) {
	orgID, ok := principalOrg(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	cve := strings.TrimSpace(r.URL.Query().Get("cve"))
	if cve == "" {
		http.Error(w, "cve query parameter is required", http.StatusBadRequest)
		return
	}

	// Vulnerable artifacts for this CVE, minus any suppressed by a not_affected
	// VEX statement (org-wide product='' or scoped to the artifact sha256), joined
	// to the environments currently running each artifact.
	rows, err := s.q(r.Context()).QueryContext(r.Context(),
		`SELECT av.artifact_sha256, a.name, av.severity,
		        e.name, e.type, sa.runtime_digest, sa.started_at
		 FROM artifact_vulnerabilities av
		 JOIN artifacts a ON a.sha256 = av.artifact_sha256
		 LEFT JOIN snapshot_artifacts sa ON sa.artifact_sha256 = av.artifact_sha256 AND sa.stopped_at IS NULL
		 LEFT JOIN environment_snapshots es ON es.id = sa.snapshot_id
		 LEFT JOIN environments e ON e.id = es.environment_id
		 WHERE av.org_id = $1 AND av.cve_id = $2
		   AND NOT EXISTS (
		     SELECT 1 FROM vex_statements vx
		     WHERE vx.org_id = av.org_id AND vx.cve_id = av.cve_id
		       AND vx.status = 'not_affected'
		       AND (vx.product = '' OR vx.product = av.artifact_sha256))
		 ORDER BY a.name, e.name NULLS LAST`, orgID, cve)
	if err != nil {
		internalError(w, err)
		return
	}
	defer rows.Close()

	type env struct {
		Environment   string `json:"environment"`
		Type          string `json:"type"`
		RuntimeDigest string `json:"runtime_digest"`
		Since         any    `json:"since"`
	}
	type artifact struct {
		SHA256       string `json:"artifact_sha256"`
		Name         string `json:"artifact_name"`
		Severity     string `json:"severity"`
		Environments []env  `json:"environments"`
	}
	byArtifact := map[string]*artifact{}
	order := []string{}
	for rows.Next() {
		var sha, name, sev string
		var envName, envType, digest *string
		var since any
		if err := rows.Scan(&sha, &name, &sev, &envName, &envType, &digest, &since); err != nil {
			internalError(w, err)
			return
		}
		a, exists := byArtifact[sha]
		if !exists {
			a = &artifact{SHA256: sha, Name: name, Severity: sev, Environments: []env{}}
			byArtifact[sha] = a
			order = append(order, sha)
		}
		if envName != nil {
			a.Environments = append(a.Environments, env{
				Environment: *envName, Type: derefStr(envType), RuntimeDigest: derefStr(digest), Since: since,
			})
		}
	}

	affected := make([]*artifact, 0, len(order))
	deployed := 0
	for _, sha := range order {
		a := byArtifact[sha]
		affected = append(affected, a)
		if len(a.Environments) > 0 {
			deployed++
		}
	}

	// How many distinct artifacts carry this CVE but are suppressed by VEX — the
	// "focus on exploitable" number.
	var suppressed int
	if err := s.q(r.Context()).QueryRowContext(r.Context(),
		`SELECT count(DISTINCT av.artifact_sha256)
		 FROM artifact_vulnerabilities av
		 WHERE av.org_id = $1 AND av.cve_id = $2
		   AND EXISTS (
		     SELECT 1 FROM vex_statements vx
		     WHERE vx.org_id = av.org_id AND vx.cve_id = av.cve_id
		       AND vx.status = 'not_affected'
		       AND (vx.product = '' OR vx.product = av.artifact_sha256))`, orgID, cve).Scan(&suppressed); err != nil {
		internalError(w, err)
		return
	}

	writeJSON(w, map[string]any{
		"cve":                     cve,
		"affected_artifacts":      affected,
		"affected_artifact_count": len(affected),
		"deployed_artifact_count": deployed,
		"vex_suppressed_count":    suppressed,
	})
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
