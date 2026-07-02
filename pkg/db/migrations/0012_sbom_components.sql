-- SBOM components (CycloneDX/SPDX ingestion): normalized package/library
-- components extracted from a software bill of materials, linked to the
-- artifact they were found in. Powers `fides search components` ("which
-- artifacts contain component X").
CREATE TABLE IF NOT EXISTS sbom_components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    artifact_sha256 VARCHAR(64) NOT NULL REFERENCES artifacts(sha256) ON DELETE CASCADE,
    attestation_id UUID REFERENCES attestations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL DEFAULT '',
    purl VARCHAR(512) NOT NULL DEFAULT '',
    licenses TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sbom_components_artifact ON sbom_components(artifact_sha256);
CREATE INDEX IF NOT EXISTS idx_sbom_components_purl ON sbom_components(purl);
CREATE INDEX IF NOT EXISTS idx_sbom_components_org_name ON sbom_components(org_id, name);
