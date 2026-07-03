-- Policy-driven auto-remediation actions for databases created before they
-- existed. Low-risk domains only (env_tag, allowlist_entry, drift_resync),
-- gated by an approval before they can be applied (see pkg/remediation).
CREATE TABLE IF NOT EXISTS remediation_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain VARCHAR(30) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'proposed',
    environment_id UUID REFERENCES environments(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES policies(id) ON DELETE SET NULL,
    reason TEXT,
    params JSONB NOT NULL DEFAULT '{}'::jsonb,
    proposed_by VARCHAR(255) NOT NULL,
    approved_by VARCHAR(255),
    applied_by VARCHAR(255),
    rejected_by VARCHAR(255),
    result_detail TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_remediation_actions_org ON remediation_actions(org_id);
CREATE INDEX IF NOT EXISTS idx_remediation_actions_env ON remediation_actions(environment_id);
CREATE INDEX IF NOT EXISTS idx_remediation_actions_status ON remediation_actions(status);
