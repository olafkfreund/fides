-- Fides Row-Level Security (RLS) — OPT-IN tenant-isolation backstop (H2)
--
-- This is defense-in-depth UNDER the application-layer org scoping. Do NOT apply
-- it until the application sets the `app.current_org` GUC on every database
-- session, otherwise all queries will return zero rows.
--
-- Application wiring required before enabling:
--   Every tenant-scoped query must run on a connection where app.current_org is
--   set to the authenticated principal's org. Use the helpers in pkg/db:
--     - db.ScopedConn(ctx, pool, org)  -> pins a conn with the GUC set (request scope)
--     - db.WithOrgScope(ctx, pool, org, fn) -> tx with SET LOCAL (self-contained work)
--   These are proven against this schema by pkg/db's RLS integration test
--   (TestScopedConnEnforcesTenantIsolationIntegration), which runs in CI.
--
-- The DB role the app connects as must NOT be a superuser or have BYPASSRLS,
-- or these policies are ignored. Create a least-privilege application role:
--
--   CREATE ROLE fides_app LOGIN PASSWORD '...';
--   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fides_app;
--   GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO fides_app;

-- Helper: read the current tenant from the session GUC as a uuid.
CREATE OR REPLACE FUNCTION fides_current_org() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.current_org', true), '')::uuid
$$;

-- Apply RLS to every table that carries a direct org_id column.
DO $$
DECLARE
  t text;
  tenant_tables text[] := ARRAY[
    'tenant_auth_configs',
    'tenant_storage_settings',
    'tenant_vault_settings',
    'tenant_llm_settings',
    'flows',
    'artifacts',
    'attestation_types',
    'environments',
    'policies',
    'system_audit_logs',
    'users',
    'sso_group_mappings'
  ];
BEGIN
  FOREACH t IN ARRAY tenant_tables LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format($f$
      CREATE POLICY tenant_isolation ON %I
        USING (org_id = fides_current_org())
        WITH CHECK (org_id = fides_current_org())
    $f$, t);
  END LOOP;
END $$;

-- Tables scoped indirectly (via a parent's org_id) need their own policies once
-- the join path is wired, e.g. trails (via flows), attestations (via trails),
-- llm_assessments (via attestations), snapshot_artifacts (via environment_snapshots).
-- These are intentionally left for a follow-up once the GUC plumbing lands.
