-- Fides Core Database Schema (PostgreSQL)

-- Enable UUID and cryptographic extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Organizations (Multi-tenancy boundary)
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Tenant SSO & OAuth Configurations (Multi-tenant authentication)
CREATE TABLE IF NOT EXISTS tenant_auth_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    provider_name VARCHAR(50) NOT NULL, -- 'github', 'gitlab', 'google', 'okta'
    client_id VARCHAR(255) NOT NULL,
    client_secret_path VARCHAR(255) NOT NULL, -- Path to secret in Vault
    auth_url VARCHAR(512),
    token_url VARCHAR(512),
    userinfo_url VARCHAR(512),
    redirect_uri VARCHAR(512) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, provider_name)
);

-- 3. Tenant Cloud Storage Configuration (Multi-tenant Evidence Storage)
CREATE TABLE IF NOT EXISTS tenant_storage_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE UNIQUE,
    storage_driver VARCHAR(50) NOT NULL DEFAULT 'local', -- 'local', 's3', 'gcs', 'azure'
    s3_endpoint VARCHAR(512),
    s3_bucket VARCHAR(255),
    s3_access_key_path VARCHAR(255), -- Path in Vault
    s3_secret_key_path VARCHAR(255), -- Path in Vault
    s3_region VARCHAR(100),
    gcs_bucket VARCHAR(255),
    gcs_credentials_path VARCHAR(255), -- Path in Vault
    azure_container VARCHAR(255),
    azure_connection_string_path VARCHAR(255), -- Path in Vault
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Tenant Cloud Vault Secrets Settings (Multi-tenant Secret Engines)
CREATE TABLE IF NOT EXISTS tenant_vault_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE UNIQUE,
    vault_provider VARCHAR(50) NOT NULL DEFAULT 'env', -- 'env', 'vault', 'aws', 'gcp', 'azure'
    vault_address VARCHAR(512),
    vault_token_path VARCHAR(255),
    vault_role VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Flows (Pipeline streams)
CREATE TABLE IF NOT EXISTS flows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    tags JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, name)
);

-- 6. Trails (Execution instances of flows, e.g. a specific CI build run)
CREATE TABLE IF NOT EXISTS trails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id UUID REFERENCES flows(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL, -- Git SHA, PR number, or Build ID
    git_repository VARCHAR(255),
    git_commit VARCHAR(40),
    git_branch VARCHAR(100),
    git_message TEXT,
    tags JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(flow_id, name)
);

-- 7. Artifacts (Build deliverables, keyed by SHA256 fingerprint)
CREATE TABLE IF NOT EXISTS artifacts (
    sha256 VARCHAR(64) PRIMARY KEY, -- SHA256 hash of the artifact
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    trail_id UUID REFERENCES trails(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'docker', 'binary', 'tarball', 'file'
    tags JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 8. Custom Attestation Types (Validation schemas and JQ rules)
CREATE TABLE IF NOT EXISTS attestation_types (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    schema JSONB, -- JSON Schema to validate payloads
    jq_rules TEXT[], -- JQ/CEL expressions for verification rules
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, name)
);

-- 9. Attestations (Check/Control results reported to trails or artifacts)
-- Supports electronic signatures for FDA 21 CFR Part 11
CREATE TABLE IF NOT EXISTS attestations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trail_id UUID REFERENCES trails(id) ON DELETE CASCADE,
    artifact_sha256 VARCHAR(64) REFERENCES artifacts(sha256) ON DELETE CASCADE, -- Nullable if attesting to the trail overall
    name VARCHAR(100) NOT NULL, -- E.g. 'sbom', 'snyk-scan', 'unit-tests'
    type_name VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL, -- Structured JSON summary
    is_compliant BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Cryptographic signing metadata for 21 CFR Part 11 compliance
    signed_by VARCHAR(255), -- IAM user/system identity
    signature TEXT, -- Cryptographic signature (RSA/ECDSA) of payload + attachments
    signature_algorithm VARCHAR(50),
    manifestation_reason TEXT, -- Statement of signature intent
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 10. Evidence Vault (Metadata for file attachments stored in S3/GCS/Azure/Local)
CREATE TABLE IF NOT EXISTS evidence_attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attestation_id UUID REFERENCES attestations(id) ON DELETE CASCADE,
    file_name VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL,
    file_hash VARCHAR(64) NOT NULL, -- SHA256 of the file content
    storage_path VARCHAR(512) NOT NULL, -- Storage bucket key
    content_type VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 11. LLM Evidence Assessments
CREATE TABLE IF NOT EXISTS llm_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attestation_id UUID REFERENCES attestations(id) ON DELETE CASCADE,
    model_provider VARCHAR(50) NOT NULL, -- 'gemini', 'openai', 'ollama', 'llamacpp'
    model_name VARCHAR(100) NOT NULL,
    prompt_template_version VARCHAR(20) NOT NULL,
    assessment_raw TEXT NOT NULL, -- Raw text output/reasoning from LLM
    compliance_score INT NOT NULL, -- 0-100 score
    findings JSONB DEFAULT '[]'::jsonb, -- List of parsed issues/threats
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 12. Environments (Runtimes monitored for running artifacts)
CREATE TABLE IF NOT EXISTS environments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'docker', 'k8s', 'ecs', 's3', 'server'
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, name)
);

-- 13. Environment Snapshots (Captures of what runs in an environment at a point in time)
CREATE TABLE IF NOT EXISTS environment_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id UUID REFERENCES environments(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 14. Snapshot Running Artifacts (Links artifacts to snapshots, establishing runtime lineage)
-- runtime_digest captures raw SHA reported by docker/k8s for shadow change comparison
CREATE TABLE IF NOT EXISTS snapshot_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID REFERENCES environment_snapshots(id) ON DELETE CASCADE,
    artifact_sha256 VARCHAR(64) REFERENCES artifacts(sha256) ON DELETE SET NULL,
    service_name VARCHAR(255) NOT NULL, -- E.g. deployment name or container name
    runtime_digest VARCHAR(255) NOT NULL, -- Direct digest reported from host daemon
    started_at TIMESTAMP WITH TIME ZONE,
    stopped_at TIMESTAMP WITH TIME ZONE
);

-- 15. Policies (Set of rules defining what is allowed to run in environments)
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    rules JSONB NOT NULL, -- YAML/JSON specification of rules
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, name)
);

-- 16. System Immutable Logs (Append-only audit trail for compliance framework audits)
CREATE TABLE IF NOT EXISTS system_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    org_id UUID NOT NULL,
    actor VARCHAR(255) NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_id UUID NOT NULL,
    old_state JSONB,
    new_state JSONB,
    request_ip VARCHAR(45),
    user_agent VARCHAR(512),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE system_audit_logs REPLICA IDENTITY FULL;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256);
CREATE INDEX IF NOT EXISTS idx_attestations_trail_id ON attestations(trail_id);
CREATE INDEX IF NOT EXISTS idx_attestations_artifact_sha256 ON attestations(artifact_sha256);
CREATE INDEX IF NOT EXISTS idx_evidence_attachments_attestation_id ON evidence_attachments(attestation_id);
CREATE INDEX IF NOT EXISTS idx_snapshot_artifacts_snapshot_id ON snapshot_artifacts(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_snapshot_artifacts_sha256 ON snapshot_artifacts(artifact_sha256);
CREATE INDEX IF NOT EXISTS idx_llm_assessments_attestation_id ON llm_assessments(attestation_id);
CREATE INDEX IF NOT EXISTS idx_system_audit_logs_org_id ON system_audit_logs(org_id);

-- 17. Users Directory
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'Viewer', -- 'Admin', 'Auditor', 'Writer', 'Viewer'
    groups VARCHAR(255)[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 18. SSO Group Mappings
CREATE TABLE IF NOT EXISTS sso_group_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    external_group VARCHAR(255) NOT NULL, -- e.g. 'github:security-team'
    role VARCHAR(50) NOT NULL, -- 'Admin', 'Auditor', 'Writer', 'Viewer'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, external_group)
);

CREATE INDEX IF NOT EXISTS idx_users_org_id ON users(org_id);
CREATE INDEX IF NOT EXISTS idx_sso_group_mappings_org_id ON sso_group_mappings(org_id);

-- 19. Tenant LLM / AI Configuration
CREATE TABLE IF NOT EXISTS tenant_llm_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE UNIQUE,
    provider_name VARCHAR(50) NOT NULL DEFAULT 'ollama', -- 'google', 'aws', 'azure', 'ollama', 'llamacpp'
    model_name VARCHAR(100) NOT NULL DEFAULT 'llama3:8b',
    endpoint_url VARCHAR(512),
    api_key_path VARCHAR(255), -- Vault path for Gemini API key, AWS secret, or Azure key
    aws_region VARCHAR(100),
    azure_deployment VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tenant_llm_settings_org_id ON tenant_llm_settings(org_id);

-- 20. Environment MCP Server Connections
CREATE TABLE IF NOT EXISTS environment_mcp_servers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id UUID REFERENCES environments(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    transport VARCHAR(20) NOT NULL DEFAULT 'stdio', -- 'stdio', 'sse'
    command VARCHAR(512),
    args TEXT[] DEFAULT '{}',
    env_vars JSONB DEFAULT '{}'::jsonb,
    url VARCHAR(512),
    auth_header VARCHAR(255), -- Vault path or encrypted string reference
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(environment_id, name)
);

CREATE INDEX IF NOT EXISTS idx_environment_mcp_servers_env_id ON environment_mcp_servers(environment_id);

-- 21. Integration Events (transactional outbox)
-- Internal plumbing for at-least-once outbound delivery (webhooks, ServiceNow,
-- CI/CD gates). Written in the same transaction as the originating change; a
-- background dispatcher leases pending rows and delivers them to sinks.
-- NOTE: intentionally NOT under RLS — the dispatcher reads across all orgs as a
-- trusted infra component; org_id is supplied explicitly at enqueue time.
CREATE TABLE IF NOT EXISTS integration_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL, -- e.g. 'snapshot.noncompliant', 'attestation.reported'
    payload JSONB NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'delivered', 'dead'
    attempts INT NOT NULL DEFAULT 0,
    last_error TEXT,
    next_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at TIMESTAMP WITH TIME ZONE
);

-- Dispatch lookup: pending rows due for delivery, oldest first.
CREATE INDEX IF NOT EXISTS idx_integration_events_dispatch
    ON integration_events(next_attempt_at)
    WHERE status = 'pending';

-- 22. Tenant Webhooks (signed outbound delivery targets)
CREATE TABLE IF NOT EXISTS tenant_webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    url VARCHAR(512) NOT NULL,
    secret_path VARCHAR(255) NOT NULL, -- HMAC signing secret reference (env/vault)
    event_types TEXT[] DEFAULT '{}',   -- empty = subscribe to all event types
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_tenant_webhooks_org_id ON tenant_webhooks(org_id);

-- 23. Tenant Git Providers (CI/CD commit-status gating)
CREATE TABLE IF NOT EXISTS tenant_git_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider VARCHAR(20) NOT NULL,    -- 'github', 'gitlab'
    host VARCHAR(255) NOT NULL,       -- github.com, gitlab.example.com (matched to the trail remote)
    api_base VARCHAR(512) NOT NULL,   -- https://api.github.com, https://gitlab.com/api/v4
    token_path VARCHAR(255) NOT NULL, -- API token secret reference (env/vault)
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(org_id, host)
);

CREATE INDEX IF NOT EXISTS idx_tenant_git_providers_org_id ON tenant_git_providers(org_id);



