-- External trust anchors for the tamper-evidence ledger (issue #297).
-- Each row records an RFC3161 timestamp over a trail's chain head at a point in
-- time, so the head can be proven to have existed independently of this database
-- (an auditor need not trust that Fides did not rewrite its own hash chain).
CREATE TABLE IF NOT EXISTS trail_anchors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    trail_id UUID NOT NULL REFERENCES trails(id) ON DELETE CASCADE,
    chain_head_hash VARCHAR(64) NOT NULL,   -- the attestation content_hash that was anchored
    tsa_url TEXT NOT NULL,
    timestamp_token BYTEA NOT NULL,         -- DER-encoded RFC3161 timestamp response
    anchored_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_trail_anchors_trail ON trail_anchors(trail_id, anchored_at DESC);
