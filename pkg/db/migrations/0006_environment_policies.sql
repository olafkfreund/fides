-- Environment policies + tags for databases created before they existed.
ALTER TABLE environments ADD COLUMN IF NOT EXISTS tags JSONB DEFAULT '{}'::jsonb;
CREATE TABLE IF NOT EXISTS environment_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    required_types TEXT[] NOT NULL DEFAULT '{}',
    if_tag VARCHAR(100),
    if_value VARCHAR(255),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(environment_id, name)
);
CREATE INDEX IF NOT EXISTS idx_environment_policies_env ON environment_policies(environment_id);
