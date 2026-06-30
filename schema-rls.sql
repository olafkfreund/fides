-- Fides Row-Level Security (RLS) — OPT-IN tenant-isolation backstop (H2)
--
-- This is defense-in-depth UNDER the application-layer org scoping. Do NOT apply
-- it until the application sets the `app.current_org` GUC on every database
-- session, otherwise all queries will return zero rows.
--
-- Application wiring required before enabling:
--   Run each request's queries inside a transaction that first executes
--     SET LOCAL app.current_org = '<authenticated principal org uuid>';
--   For database/sql with a pool, the cleanest approach is a helper that opens a
--   tx, sets the GUC, runs the work, and commits, e.g.:
--
--     func (s *Server) withOrgScope(ctx context.Context, org uuid.UUID,
--         fn func(*sql.Tx) error) error {
--         tx, err := s.DB.BeginTx(ctx, nil)
--         if err != nil { return err }
--         defer tx.Rollback()
--         if _, err := tx.ExecContext(ctx, "SET LOCAL app.current_org = $1", org.String()); err != nil {
--             return err
--         }
--         if err := fn(tx); err != nil { return err }
--         return tx.Commit()
--     }
--
-- The DB role the app connects as must NOT be a superuser or have BYPASSRLS,
-- or these policies are ignored.

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
