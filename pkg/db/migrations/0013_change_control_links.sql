-- Change <-> Control linkage (#227): records that a ServiceNow change
-- (CHGxxxx) implemented a Fides control via a specific attestation, so both
-- Fides and the ServiceNow change_request reference the same evidence.
CREATE TABLE IF NOT EXISTS change_control_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    trail_id UUID NOT NULL REFERENCES trails(id) ON DELETE CASCADE,
    control_id UUID NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    attestation_id UUID NOT NULL REFERENCES attestations(id) ON DELETE CASCADE,
    change_number VARCHAR(100) NOT NULL,      -- ServiceNow change_request number, e.g. CHG0030192
    change_sys_id VARCHAR(100),               -- change_request sys_id, once resolved via ServiceNow
    linked_by VARCHAR(255) NOT NULL,          -- principal (email or service-account) that recorded the link
    servicenow_synced BOOLEAN NOT NULL DEFAULT FALSE, -- whether the change_request write-back succeeded
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(trail_id, control_id, change_number)
);
CREATE INDEX IF NOT EXISTS idx_change_control_links_org ON change_control_links(org_id);
CREATE INDEX IF NOT EXISTS idx_change_control_links_control ON change_control_links(control_id);
CREATE INDEX IF NOT EXISTS idx_change_control_links_change_number ON change_control_links(change_number);
