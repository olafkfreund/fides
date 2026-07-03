#!/usr/bin/env bash
# Fides database bootstrap — idempotent, run once for a brand-new install.
#
# It applies the schema, creates the least-privilege application role that
# Row-Level Security requires, applies the RLS policies, and seeds the first
# organization (tenant). At the end it prints the two values you must wire into
# the fides-server deployment: FIDES_API_ORG_ID and the fides_app DB_DSN.
#
# Run it as a role that OWNS the database (e.g. the postgres/fides_user superuser
# used to create the DB) — NOT as fides_app.
#
# Usage:
#   PGHOST=localhost PGPORT=5432 PGUSER=fides_user PGPASSWORD=... PGDATABASE=fides \
#   ORG_NAME="Acme Corp" FIDES_APP_PASSWORD="<pick-a-strong-password>" \
#   ./scripts/setup-db.sh
#
# FIDES_APP_PASSWORD is optional; if unset a random one is generated and printed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
: "${PGDATABASE:=fides}"
: "${ORG_NAME:=Default Organization}"
: "${FIDES_APP_PASSWORD:=$(openssl rand -hex 20)}"
PSQL=(psql -v ON_ERROR_STOP=1 -X -q)

echo "==> 1/4 Applying base schema (idempotent)"
"${PSQL[@]}" -f "$HERE/schema.sql" >/dev/null

echo "==> 2/4 Creating least-privilege application role 'fides_app'"
"${PSQL[@]}" <<SQL >/dev/null
DO \$\$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='fides_app') THEN
    ALTER ROLE fides_app WITH LOGIN PASSWORD '${FIDES_APP_PASSWORD}' NOSUPERUSER NOBYPASSRLS;
  ELSE
    CREATE ROLE fides_app LOGIN PASSWORD '${FIDES_APP_PASSWORD}' NOSUPERUSER NOBYPASSRLS;
  END IF;
END \$\$;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fides_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO fides_app;
GRANT CREATE, USAGE ON SCHEMA public TO fides_app;                 -- for boot migrations
GRANT "${PGUSER:-fides_user}" TO fides_app;                        -- ALTER existing tables in future migrations
ALTER DEFAULT PRIVILEGES FOR ROLE "${PGUSER:-fides_user}" IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO fides_app;
ALTER DEFAULT PRIVILEGES FOR ROLE "${PGUSER:-fides_user}" IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO fides_app;
SQL

echo "==> 3/4 Applying Row-Level Security policies"
"${PSQL[@]}" -f "$HERE/schema-rls.sql" >/dev/null

echo "==> 4/4 Seeding the first organization"
ORG_ID=$("${PSQL[@]}" -tA <<SQL
INSERT INTO organizations (name) VALUES ('${ORG_NAME}')
ON CONFLICT DO NOTHING;
SELECT id FROM organizations WHERE name = '${ORG_NAME}' ORDER BY created_at LIMIT 1;
SQL
)

cat <<DONE

✅ Database ready. Wire these into the fides-server deployment / fides-secrets:

  FIDES_API_ORG_ID = ${ORG_ID}
  DB_DSN           = host=${PGHOST:-fides-db} port=${PGPORT:-5432} user=fides_app password=${FIDES_APP_PASSWORD} dbname=${PGDATABASE} sslmode=${PGSSLMODE:-disable}

Also set on the deployment:
  FIDES_RLS_ENABLED = true
  PORTAL_USERNAME / PORTAL_PASSWORD  (admin login for the portal)

Keep the fides_app password safe — it is shown only once.
DONE
