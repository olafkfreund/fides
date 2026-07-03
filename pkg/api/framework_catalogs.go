package api

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// controlTemplate is one control in a framework catalog, mapped to the Fides
// evidence/attestation types that satisfy it.
type controlTemplate struct {
	Key           string   `json:"key"`
	Name          string   `json:"name"`
	RequiredTypes []string `json:"required_types"`
}

// frameworkCatalogs seeds ready-made control catalogs per regulated framework,
// so an org can adopt a framework in one click (parity with Chainloop's built-in
// frameworks). Controls map to our evidence types: junit, snyk, trivy,
// sbom-cyclonedx, secret-scan, iac-scan-terraform, sast-semgrep-scan, deployment,
// and the supply-chain provenance types cosign-verification (Sigstore/cosign
// signature verification, from `fides verify-image`) and slsa-provenance (SLSA
// in-toto build provenance, from `fides attest slsa|fetch`). Any type listed
// here contributes to control coverage and the change-gate risk score.
var frameworkCatalogs = map[string][]controlTemplate{
	"SOC2": {
		{"SOC2-CC6.1", "Secrets are not committed", []string{"secret-scan"}},
		{"SOC2-CC7.1", "Artifacts pass vulnerability scanning", []string{"trivy", "snyk"}},
		{"SOC2-CC7.2", "Software bill of materials produced", []string{"sbom-cyclonedx"}},
		{"SOC2-CC7.3", "Build provenance (SLSA in-toto)", []string{"slsa-provenance"}},
		{"SOC2-CC8.1", "Changes are covered by passing tests", []string{"junit"}},
	},
	"ISO27001": {
		{"ISO-A.12.6.1", "Technical vulnerability management", []string{"snyk", "trivy"}},
		{"ISO-A.14.2.8", "System security testing", []string{"junit", "sast-semgrep-scan"}},
		{"ISO-A.12.1.2", "Change management", []string{"deployment"}},
		{"ISO-A.14.2.5", "Secure engineering (SBOM)", []string{"sbom-cyclonedx"}},
	},
	"NIST-800-53": {
		{"NIST-RA-5", "Vulnerability scanning", []string{"trivy", "snyk"}},
		{"NIST-SA-11", "Developer security testing", []string{"junit", "sast-semgrep-scan"}},
		{"NIST-CM-3", "Configuration change control", []string{"deployment", "iac-scan-terraform"}},
		{"NIST-SR-4", "Provenance (SBOM)", []string{"sbom-cyclonedx"}},
		{"NIST-SR-3", "Supply chain — build provenance", []string{"slsa-provenance"}},
		{"NIST-SR-11", "Component authenticity (signature verification)", []string{"cosign-verification"}},
	},
	"PCI-DSS": {
		{"PCI-6.2", "Patch / vulnerability management", []string{"snyk", "trivy"}},
		{"PCI-6.3", "Secure software development", []string{"sast-semgrep-scan"}},
		{"PCI-6.5", "Common coding vulnerabilities addressed", []string{"sast-semgrep-scan", "secret-scan"}},
		{"PCI-11.3", "Vulnerability scanning of releases", []string{"trivy"}},
	},
	"DORA": {
		{"DORA-ICT-RISK", "ICT risk — vulnerability management", []string{"snyk", "trivy"}},
		{"DORA-RESILIENCE-TEST", "Resilience / operational testing", []string{"junit"}},
		{"DORA-CHANGE-MGMT", "ICT change management", []string{"deployment"}},
		{"DORA-THIRD-PARTY", "Third-party / supply-chain (SBOM)", []string{"sbom-cyclonedx"}},
	},
	"PSD2": {
		{"PSD2-CODE-SECURITY", "Secure code (SAST + secrets)", []string{"sast-semgrep-scan", "secret-scan"}},
		{"PSD2-VULN-MGMT", "Vulnerability management", []string{"snyk", "trivy"}},
		{"PSD2-CHANGE-CONTROL", "Change control", []string{"deployment"}},
	},
	"SOX": {
		{"SOX-ITGC-CHANGE", "IT general controls — change management", []string{"deployment", "junit"}},
		{"SOX-VULN", "Vulnerability remediation", []string{"snyk", "trivy"}},
		{"SOX-SEGREGATION", "Segregation of duties on deploys", []string{"deployment"}},
	},
	// SLSA is a dedicated supply-chain integrity catalog (EU CRA / NIST SSDF
	// aligned): build provenance, artifact signature verification, and an SBOM.
	// Each control maps to one recognized supply-chain evidence type so the
	// change gate can require SLSA/cosign/SBOM as first-class gate evidence.
	"SLSA": {
		{"SLSA-BUILD-PROV", "Build provenance (SLSA in-toto)", []string{"slsa-provenance"}},
		{"SLSA-SIG-VERIFY", "Artifact signature verified (cosign/Sigstore)", []string{"cosign-verification"}},
		{"SLSA-SBOM", "Software bill of materials", []string{"sbom-cyclonedx"}},
	},
}

// handleListFrameworks returns the available framework catalogs (name + controls).
func (s *Server) handleListFrameworks(w http.ResponseWriter, r *http.Request) {
	if _, ok := principalOrg(r); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	out := []map[string]any{}
	for name, controls := range frameworkCatalogs {
		out = append(out, map[string]any{"framework": name, "controls": controls})
	}
	writeJSON(w, out)
}

// handleImportFramework upserts a framework's control catalog into the org's controls.
func (s *Server) handleImportFramework(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Framework string `json:"framework"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, err)
		return
	}
	catalog, exists := frameworkCatalogs[req.Framework]
	if !exists {
		http.Error(w, "unknown framework", http.StatusBadRequest)
		return
	}
	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w, err)
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(r.Context(), "SELECT set_config('app.current_org', $1, true)", p.OrgID.String()); err != nil {
		internalError(w, err)
		return
	}
	for _, c := range catalog {
		if _, err := tx.ExecContext(r.Context(),
			`INSERT INTO controls (id, org_id, key, name, framework, required_types)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 ON CONFLICT (org_id, key) DO UPDATE SET
			   name = EXCLUDED.name, framework = EXCLUDED.framework,
			   required_types = EXCLUDED.required_types, archived = FALSE`,
			uuid.New(), p.OrgID, c.Key, c.Name, req.Framework, pq.StringArray(c.RequiredTypes)); err != nil {
			internalError(w, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"framework": req.Framework, "imported": len(catalog)})
}
