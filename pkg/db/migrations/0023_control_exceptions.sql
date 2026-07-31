-- Time-boxed control exceptions (waivers). An in-date, non-revoked exception for
-- a control key lets the change-gate treat that control as "waived" rather than
-- failed/missing — a governed, auditable way to unblock a deploy without routing
-- around the gate. expires_at is mandatory: every waiver is time-boxed.
CREATE TABLE IF NOT EXISTS control_exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    control_key VARCHAR(100) NOT NULL,
    reason TEXT NOT NULL,
    approved_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_control_exceptions_org ON control_exceptions(org_id, control_key);
