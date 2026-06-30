-- Service accounts + API keys for databases created before they existed.
CREATE TABLE IF NOT EXISTS service_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'Writer',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, name)
);
CREATE TABLE IF NOT EXISTS service_account_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_account_id UUID NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    prefix VARCHAR(32) NOT NULL UNIQUE,
    key_hash VARCHAR(255) NOT NULL,
    label VARCHAR(100),
    expires_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_service_account_keys_prefix ON service_account_keys(prefix);
