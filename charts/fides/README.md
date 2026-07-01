# Fides Helm chart

Installs Fides (server + service + optional ingress) and **seeds the database in
one step**: a pre-install/pre-upgrade Job applies the schema, creates the
least-privilege `fides_app` RLS role, applies the RLS policies, and seeds the
first organization.

## Quick start

```bash
helm install fides ./charts/fides \
  --namespace fides --create-namespace \
  --set image.repository=<your-registry>/fides-server \
  --set image.tag=<tag> \
  --set database.host=<postgres-host> \
  --set database.ownerUser=fides_user \
  --set database.ownerPassword=<owner-pw> \
  --set database.appPassword=<pick-strong-pw> \
  --set org.id=$(uuidgen) \
  --set org.name="Acme Corp" \
  --set portal.username=admin \
  --set portal.password=<admin-pw> \
  --set secrets.encryptionKey=$(head -c 32 /dev/urandom | base64) \
  --set secrets.apiToken=$(head -c 32 /dev/urandom | base64)
```

Then follow the printed NOTES (view seed logs, wait for rollout, log in).

## Key values

| Value | Purpose |
|-------|---------|
| `org.id` / `org.name` | first tenant (set `org.id` to a UUID for a deterministic install) |
| `rls.enabled` | enforce Postgres RLS tenant isolation (default `true`) |
| `database.ownerUser/Password` | admin role used **only** by the seed job |
| `database.appUser/appPassword` | least-privilege role the server runs as |
| `portal.username/password` | portal admin login |
| `secrets.existingSecret` | use an out-of-band Secret instead of rendering one (prod) |
| `env.SECRETS_PROVIDER` | `env` or `aws` (per-tenant integration secrets) |
| `ingress.*` | expose the portal |

## Notes

- `files/schema.sql` and `files/schema-rls.sql` are **copies** of the repo-root
  files, bundled so the seed Job is self-contained. Keep them in sync when the
  schema changes.
- For production, prefer `secrets.existingSecret` (SealedSecret / ExternalSecret)
  over passing secret values through `--set`.
- See `docs/setup.md` for the full manual walkthrough and the upgrade-to-RLS path.
