-- Deployment anchors (evidence that a signed deployment attestation was
-- anchored to a ServiceNow CMDB CI on change close / deploy) for existing
-- databases.
CREATE TABLE IF NOT EXISTS deployment_anchors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    trail_id UUID NOT NULL REFERENCES trails(id) ON DELETE CASCADE,
    attestation_id UUID REFERENCES attestations(id) ON DELETE SET NULL,
    ci_sys_id VARCHAR(64) NOT NULL,
    ci_name VARCHAR(255),
    change_number VARCHAR(100),
    image_digest VARCHAR(64),
    commit_sha VARCHAR(40),
    build_log_ref TEXT,
    runtime_snapshot_ref VARCHAR(64),
    content_hash VARCHAR(64),
    compliant BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_deployment_anchors_org_id ON deployment_anchors(org_id);
CREATE INDEX IF NOT EXISTS idx_deployment_anchors_trail_id ON deployment_anchors(trail_id);
