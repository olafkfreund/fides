ALTER TABLE cra_case_deadlines
    ADD COLUMN IF NOT EXISTS due_soon_enqueued_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS overdue_enqueued_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_cra_deadlines_reminder_due
    ON cra_case_deadlines (org_id, due_at)
    WHERE superseded_at IS NULL AND satisfied_at IS NULL AND overdue_enqueued_at IS NULL;

-- Background tenant discovery exposes only UUIDs. Deadline and case reads
-- still require the tenant scope, like the tenant lookups made by outbox sinks.
CREATE TABLE IF NOT EXISTS cra_reminder_orgs (
    org_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE
);

ALTER TABLE cra_reminder_orgs ENABLE ROW LEVEL SECURITY;
ALTER TABLE cra_reminder_orgs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON cra_reminder_orgs;
CREATE POLICY tenant_isolation ON cra_reminder_orgs FOR SELECT
    USING (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid
        OR NULLIF(current_setting('app.current_org', true), '') IS NULL);
DROP POLICY IF EXISTS cra_reminder_org_insert ON cra_reminder_orgs;
CREATE POLICY cra_reminder_org_insert ON cra_reminder_orgs FOR INSERT
    WITH CHECK (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid);

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'fides_app') THEN
        GRANT SELECT, INSERT ON cra_reminder_orgs TO fides_app;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION cra_register_reminder_org() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE format('INSERT INTO %I.cra_reminder_orgs (org_id) VALUES ($1) ON CONFLICT DO NOTHING', TG_TABLE_SCHEMA)
        USING NEW.org_id;
    RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS cra_register_reminder_org ON cra_case_deadlines;
CREATE TRIGGER cra_register_reminder_org AFTER INSERT OR UPDATE OF org_id ON cra_case_deadlines
    FOR EACH ROW EXECUTE FUNCTION cra_register_reminder_org();

-- ALTER TABLE already holds an exclusive lock until the migration commits.
-- Let the table owner backfill existing tenant IDs under that lock.
DO $$
DECLARE
    was_forced BOOLEAN;
BEGIN
    SELECT relforcerowsecurity INTO was_forced
        FROM pg_class WHERE oid = 'cra_case_deadlines'::regclass;
    IF was_forced THEN
        ALTER TABLE cra_case_deadlines NO FORCE ROW LEVEL SECURITY;
    END IF;
    ALTER TABLE cra_reminder_orgs NO FORCE ROW LEVEL SECURITY;
    INSERT INTO cra_reminder_orgs (org_id)
    SELECT DISTINCT org_id FROM cra_case_deadlines
    ON CONFLICT DO NOTHING;
    ALTER TABLE cra_reminder_orgs FORCE ROW LEVEL SECURITY;
    IF was_forced THEN
        ALTER TABLE cra_case_deadlines FORCE ROW LEVEL SECURITY;
    END IF;
END $$;
