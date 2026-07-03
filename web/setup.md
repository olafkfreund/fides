# Fides — Database Seeding & Brand-New Setup

This is the complete, do-it-once guide to stand up Fides on a fresh cluster or
host. It covers the database, the Row-Level Security (RLS) application role, the
first organization (tenant), and the admin login.

> **Why the extra role?** Fides enforces Postgres RLS for tenant isolation, so
> the application connects as a **least-privilege `fides_app` role** (not a
> superuser). `scripts/setup-db.sh` creates it for you.

## 1. Prerequisites

- PostgreSQL 15+ reachable from the API server.
- A database (default name `fides`) owned by an admin role (e.g. `fides_user`)
  used only for setup and migrations.
- `psql` and `openssl` on the machine running the setup script.

## 2. Seed the database (one command)

Run the bootstrap script as the **owner** role. It applies the schema, creates
the `fides_app` RLS role, applies the RLS policies, and seeds the first org:

```bash
PGHOST=<db-host> PGPORT=5432 PGUSER=fides_user PGPASSWORD=<owner-pw> PGDATABASE=fides \
ORG_NAME="Acme Corp" FIDES_APP_PASSWORD="<pick-a-strong-password>" \
./scripts/setup-db.sh
```

It is **idempotent** — safe to re-run. It prints the two values you need next:

```
FIDES_API_ORG_ID = 4e70c5ad-...        # the tenant UUID
DB_DSN           = host=... user=fides_app password=... dbname=fides sslmode=disable
```

If you omit `FIDES_APP_PASSWORD` a random one is generated and printed once.

## 3. Create the secrets

Create the `fides-secrets` Secret (see `kubernetes/fides-secrets.example.yaml`).
The `db-dsn` **must use the `fides_app` DSN printed above** (not `fides_user`):

```bash
kubectl -n fides create secret generic fides-secrets \
  --from-literal=db-dsn='host=fides-db port=5432 user=fides_app password=<app-pw> dbname=fides sslmode=disable' \
  --from-literal=postgres-password='<owner-pw>' \
  --from-literal=encryption-key='<32-random-bytes-base64>' \
  --from-literal=api-token='<random-token>' \
  --from-literal=portal-password='<admin-login-password>'
```

## 4. Configure the deployment

Set these on `fides-server` (already in `kubernetes/fides-deploy.yaml`; fill the
tenant/admin values):

| Env | Value |
|-----|-------|
| `FIDES_API_ORG_ID` | the tenant UUID from step 2 |
| `PORTAL_USERNAME` | admin login name (e.g. `admin`) |
| `PORTAL_PASSWORD` | from the `portal-password` secret |
| `FIDES_RLS_ENABLED` | `true` |
| `SECRETS_PROVIDER` | `aws` (per-tenant integration secrets) or `env` |

## 5. Deploy & first login

```bash
kubectl apply -f kubernetes/fides-deploy.yaml
kubectl -n fides rollout status deploy/fides-server
```

On first boot the server applies its embedded migrations (as `fides_app`, which
the setup script granted the needed privileges). Then log in at the portal with
`PORTAL_USERNAME` / `PORTAL_PASSWORD`.

## 6. Verify

```bash
# app up + tenant-scoped read works
curl -s -c cj -X POST https://<host>/api/v1/auth/local-login \
  -H 'content-type: application/json' -d '{"username":"admin","password":"<pw>"}'
curl -s -b cj https://<host>/api/v1/flows        # returns only this org's flows
```

RLS isolation is enforced at the database layer: with no `app.current_org` set a
query returns **zero rows** (fail-closed), and cross-tenant writes raise a
row-level-security violation.

## 7. Add users & more tenants

- **More admins/users:** create rows in `users` (org-scoped) or manage them in
  the portal Settings → Users tab.
- **Additional tenants:** insert another `organizations` row and run a separate
  `fides-server` (or tenant routing) with that `FIDES_API_ORG_ID`.

## Upgrading an existing install to RLS

If you already run Fides as a superuser DB role, run `scripts/setup-db.sh` (it
creates `fides_app` + applies the policies without disrupting the running app,
which still bypasses RLS as superuser), then switch `db-dsn` to the `fides_app`
DSN and set `FIDES_RLS_ENABLED=true`, and restart. Keep the old DSN handy to roll
back.
