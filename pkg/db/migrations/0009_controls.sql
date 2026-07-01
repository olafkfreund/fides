-- Governance controls for databases created before they existed.
CREATE TABLE IF NOT EXISTS controls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    key VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    framework VARCHAR(50),
    required_types TEXT[] NOT NULL DEFAULT '{}',
    archived BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, key)
);
CREATE INDEX IF NOT EXISTS idx_controls_org ON controls(org_id);
