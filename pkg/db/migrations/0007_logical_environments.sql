-- Logical environments for databases created before they existed.
CREATE TABLE IF NOT EXISTS logical_environments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, name)
);
CREATE TABLE IF NOT EXISTS logical_environment_members (
    logical_id UUID NOT NULL REFERENCES logical_environments(id) ON DELETE CASCADE,
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    PRIMARY KEY (logical_id, environment_id)
);
