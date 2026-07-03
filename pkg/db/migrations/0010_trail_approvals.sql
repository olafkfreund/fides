-- Trail approvals (segregation-of-duties evidence) for existing databases.
CREATE TABLE IF NOT EXISTS trail_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    trail_id UUID NOT NULL REFERENCES trails(id) ON DELETE CASCADE,
    approved_by VARCHAR(255) NOT NULL,
    approver_kind VARCHAR(20) NOT NULL,
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(trail_id, approved_by)
);
CREATE INDEX IF NOT EXISTS idx_trail_approvals_trail ON trail_approvals(trail_id);
