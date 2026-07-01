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
    'sso_group_mappings',
    'tenant_webhooks',
    'tenant_git_providers',
    'tenant_servicenow_settings',
    'tenant_slack_settings',
    'controls',
    'trail_approvals',
    'integration_events',
    'logical_environments',
    'service_accounts'
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

-- Tables scoped indirectly (via a parent's org_id). Their policy references the
-- parent by foreign key; because the parent table is itself RLS-protected, the
-- subquery `SELECT id FROM parent` already returns only the current tenant's
-- rows, so the isolation chains automatically (flows -> trails -> attestations
-- -> llm_assessments/evidence_attachments; environments -> environment_snapshots
-- -> snapshot_artifacts; environments -> environment_mcp_servers).
DO $$
DECLARE
  rec record;
  child_tables jsonb := '[
    {"tbl": "trails",                  "fk": "flow_id",        "parent": "flows"},
    {"tbl": "attestations",            "fk": "trail_id",       "parent": "trails"},
    {"tbl": "llm_assessments",         "fk": "attestation_id", "parent": "attestations"},
    {"tbl": "evidence_attachments",    "fk": "attestation_id", "parent": "attestations"},
    {"tbl": "environment_snapshots",   "fk": "environment_id", "parent": "environments"},
    {"tbl": "snapshot_artifacts",      "fk": "snapshot_id",    "parent": "environment_snapshots"},
    {"tbl": "environment_mcp_servers", "fk": "environment_id", "parent": "environments"},
    {"tbl": "environment_allowlist",   "fk": "environment_id", "parent": "environments"},
    {"tbl": "environment_policies",    "fk": "environment_id", "parent": "environments"},
    {"tbl": "logical_environment_members", "fk": "logical_id", "parent": "logical_environments"},
    {"tbl": "service_account_keys",    "fk": "service_account_id", "parent": "service_accounts"}
  ]'::jsonb;
BEGIN
  FOR rec IN SELECT * FROM jsonb_to_recordset(child_tables) AS x(tbl text, fk text, parent text) LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', rec.tbl);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', rec.tbl);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', rec.tbl);
    EXECUTE format($f$
      CREATE POLICY tenant_isolation ON %I
        USING (%I IN (SELECT id FROM %I))
        WITH CHECK (%I IN (SELECT id FROM %I))
    $f$, rec.tbl, rec.fk, rec.parent, rec.fk, rec.parent);
  END LOOP;
END $$;

-- The organizations root table: a session may only see its own org row.
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON organizations;
CREATE POLICY tenant_isolation ON organizations
  USING (id = fides_current_org())
  WITH CHECK (id = fides_current_org());
