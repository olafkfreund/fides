-- Per-environment artifact allow-list for databases created before it existed.
CREATE TABLE IF NOT EXISTS environment_allowlist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    artifact_sha256 VARCHAR(64) NOT NULL,
    approved_by VARCHAR(255),
    reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(environment_id, artifact_sha256)
);
CREATE INDEX IF NOT EXISTS idx_environment_allowlist_env ON environment_allowlist(environment_id);
