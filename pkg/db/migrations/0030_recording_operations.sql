CREATE TABLE IF NOT EXISTS recording_operations (
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    operation_id UUID NOT NULL,
    endpoint TEXT NOT NULL,
    fingerprint BYTEA NOT NULL CHECK (octet_length(fingerprint) = 32),
    response BYTEA NOT NULL,
    PRIMARY KEY (org_id, operation_id)
);

-- Install the policy with the table so a separately migrated runtime is also protected.
ALTER TABLE recording_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE recording_operations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON recording_operations;
CREATE POLICY tenant_isolation ON recording_operations
    USING (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid)
    WITH CHECK (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid);

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'fides_app') THEN
        GRANT SELECT, INSERT ON recording_operations TO fides_app;
    END IF;
END $$;
