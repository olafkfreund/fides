-- Vulnerability impact index + VEX (issue #294).
--
-- artifact_vulnerabilities: CVE IDs extracted from vulnerability-scan
-- attestations (trivy/snyk/sarif) and linked to the artifact they were found in,
-- so we can answer "which running environments ship CVE-X?" by joining through
-- snapshot_artifacts. CVEs otherwise live only as findings[] strings inside the
-- attestation payload and are not queryable.
CREATE TABLE IF NOT EXISTS artifact_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    artifact_sha256 VARCHAR(64) NOT NULL REFERENCES artifacts(sha256) ON DELETE CASCADE,
    attestation_id UUID REFERENCES attestations(id) ON DELETE CASCADE,
    cve_id VARCHAR(64) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT '',
    source VARCHAR(20) NOT NULL DEFAULT '',   -- trivy | snyk | sarif
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (artifact_sha256, cve_id, attestation_id)
);
CREATE INDEX IF NOT EXISTS idx_artifact_vulns_cve ON artifact_vulnerabilities(org_id, cve_id);
CREATE INDEX IF NOT EXISTS idx_artifact_vulns_artifact ON artifact_vulnerabilities(artifact_sha256);

-- vex_statements: Vulnerability Exploitability eXchange assertions. A
-- status='not_affected' statement suppresses a CVE from the impact query so
-- teams focus on exploitable vulnerabilities, not raw scanner output. product
-- is empty for an org-wide statement, or an artifact sha256 to scope it to one
-- artifact.
CREATE TABLE IF NOT EXISTS vex_statements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cve_id VARCHAR(64) NOT NULL,
    product VARCHAR(128) NOT NULL DEFAULT '',   -- '' = org-wide, or artifact sha256
    status VARCHAR(32) NOT NULL,                -- not_affected | affected | fixed | under_investigation
    justification TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_vex_cve ON vex_statements(org_id, cve_id);
