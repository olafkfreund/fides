# Upgrading Fides

Behaviour changes that alter what Fides *does* rather than what it offers — the
kind that look like a regression if you meet them without warning. New features
are not listed here; the release notes cover those.

Fides is `v0.x`. Anything may change, and this document is where the changes
that can bite an existing deployment get written down.

## v0.8.3

### A published binary now creates a CMDB CI, where it previously created nothing

An artifact reported with `--type binary` (or `tarball`, `jar`, `file`) was
silently dropped by the ServiceNow CMDB sink. The class switch matched only the
container types and fell through to a bare `return nil`, so the event was
recorded as delivered, no CI was created, and nothing was logged. A change could
anchor to nothing while looking entirely healthy.

Those artifacts now become **`cmdb_ci_spkg`** (Software Package) records, with
the full digest in `short_description` and dedupe by a `LIKE` on it — the same
convention every other digest-bearing CI here uses. Container images are
unaffected, and an absent `--type` still means `docker`, so nothing already
reported is reclassified.

**Nothing to do if you do not run the CMDB sink** (`FIDES_SNOW_CMDB_ENABLED`),
or if you only ever report container images.

**If you do**, expect new `cmdb_ci_spkg` records to start appearing for
binaries. Check that the integration user can write that table before upgrading:

```text
GET /api/now/table/cmdb_ci_spkg?sysparm_limit=1
```

If writes are denied, the failure is now *visible* rather than silent — the
event returns an error, retries 8 times with exponential backoff, and is
dead-lettered with the reason in `integration_events.last_error`. That is the
intended trade: a dead-lettered event you can find beats a delivery that
reported success and did nothing.

Note that `cmdb_sw_component_install` is deliberately **not** used, though it is
the instinctive place to model a published jar. It is Discovery/SAM-owned in the
CMDB Data Foundation and write-guarded: the Table API returns 403 even for an
active admin with `admin_overrides` set on every ACL, and IRE refuses it with
`IDENTIFICATION_RULE_MISSING`.

## v0.8.2

### Seven more tables came under row-level security

`artifact_vulnerabilities`, `control_exceptions`, `sbom_components`,
`service_owners`, `trail_anchors`, `training_records` and `vex_statements` now
carry a `tenant_isolation` policy. They always had an `org_id` and were always
scoped in-query; what changed is that the database enforces it too. A gate now
fails the build if a future table with `org_id` arrives without one
(`TestEveryOrgScopedTableHasAnRLSPolicyIntegration`).

**Nothing to do if `FIDES_RLS_ENABLED=false`, or if you connect as a
superuser** — no policy is enforced in either case.

**Where RLS is effective**, this is the same rolling-update shape as v0.8.0, and
smaller: a pod that reads one of those seven on a connection with no tenant set
now sees zero rows rather than all of them. Every read of them in Fides is a
request-path query that sets the tenant, so this only bites something outside
Fides reading those tables on a pooled connection — a reporting job, a BI tool,
a hand-written script. If you have one, give it a superuser role or set
`app.current_org` before it queries.

Three tables are deliberately **not** covered and must never be:
`sessions`, `service_accounts` and `integration_events`. Each is read before the
tenant is known — a session is looked up *to discover* its org — so a policy
there hides every row and breaks login, API keys, or event delivery
respectively. The gate above asserts their absence rather than tolerating it,
because that mistake has been made here before.

## v0.8.0

### The TSA endpoint must be one you configured

`POST /api/v1/trails/{id}/anchor` accepts a `tsa_url` in its body. It no longer
supplies a destination — it **selects** one:

- **`FIDES_TSA_URL`** is the default, used when `tsa_url` is absent; and
- **`FIDES_TSA_URLS`** (comma-separated) offers further endpoints callers may
  choose between.

A `tsa_url` that does not match one of those exactly is refused, and what
reaches the network is the string **as you configured it**, not the one that
arrived in the request.

**Nothing to do if callers rely on the server's TSA** — an absent or matching
`tsa_url` behaves as before. **If callers pass their own**, list those endpoints
in `FIDES_TSA_URLS`.

#### Why matching is not enough on its own

An earlier version of this allowed any URL on an approved *host*. That still let
the caller supply the path, the query and the userinfo — so
`https://tsa.example/../../collect?leak=1` passed a host check while being a
different request entirely. Substituting our own copy after matching is what
ends that: the request chooses among endpoints, and cannot describe one.

It also matters more than a dial guard here. The guard stops a request landing
on an internal address however the name resolves; it has nothing to say about a
caller naming a host they control on the public internet, and a timestamp
request carries a trail's chain-head hash.

#### An internal TSA on a private address no longer works

The dial guard mentioned above is enforced at connection time and has **no
opt-out**: loopback, RFC1918 private ranges, link-local (which covers the cloud
metadata endpoint) and the unspecified address are all refused, whatever the
hostname resolves to. Carrier-grade NAT (`100.64.0.0/10`) is deliberately not
blocked, so a TSA reached over a tailnet still works.

If you run your own RFC3161 timestamp authority on an internal address —
`https://tsa.internal` resolving to `10.0.x.x`, say — **anchoring stops
working on this version and there is no flag to re-enable it.** Either publish
the TSA on a routable address or reach it over a tailnet. Trails still record
and verify without an anchor; `verify-chain` reports the anchor as absent
rather than failing.

### Tenant isolation (RLS) is on by default

`FIDES_RLS_ENABLED` used to be opt-in. It is now **on unless you set it to
exactly `false`** — a typo leaves the backstop in place rather than silently
removing it.

**Why it changed.** With RLS off, the request connection is unscoped, so a
handler that forgot to filter on the caller's organization had no isolation at
all. Four separate cross-tenant defects were found that way in a single day
(#456, #457, #458, #460). Every handler scopes its own queries now; a backstop
exists for the fifth one nobody found.

**Nothing to do if you already set it.** An explicit `true` or `false` is
honoured exactly as before.

#### It does nothing unless you connect as a non-superuser

A PostgreSQL superuser ignores every row-level security policy, including
`FORCE ROW LEVEL SECURITY`. So does any role holding `BYPASSRLS`. The stock
`postgres` image creates `POSTGRES_USER` as a superuser — which means the
obvious deployment applies the policies, sets the tenant on every request, logs
`RLS policies applied`, and isolates nothing.

Measured, rather than assumed:

| connection | rows visible |
|---|---|
| non-superuser, tenant not set | **none** |
| non-superuser, tenant set | its own |
| superuser, either way | **everything** |

**The server now refuses to start.** On startup it checks whether the policies
can constrain its own connection and, if they cannot, it stops with an error
naming the role and both ways forward.

This was a warning first, and a warning was the wrong shape. The deployment it
fires on is precisely the one that believes it has database-level isolation and
does not — and a `WARNING` at boot is read by nobody three weeks later, sitting
directly beneath a cheerful `RLS policies applied`.

It is safe to adopt because it only fires when RLS is switched **on**. A
deployment that has deliberately turned it off never reaches the check. Every
boot this interrupts is one claiming an isolation it does not have.

If you are that deployment, you have two ways forward and the error message
carries both:

1. **Connect as a role RLS can constrain** — not a superuser, no `BYPASSRLS`.
   The recipe is below.
2. **Set `FIDES_RLS_ENABLED=false`** and run on handler-level scoping alone.
   This is a real option rather than a workaround — the handlers scope every
   query themselves, and that is the primary control. The point of making it
   explicit is that it becomes a decision someone typed, instead of a line in a
   log nobody read.

To make it real, connect as a least-privilege role — the recipe is commented at
the top of `schema-rls.sql`:

```sql
CREATE ROLE fides_app LOGIN PASSWORD '…' NOSUPERUSER NOBYPASSRLS;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fides_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO fides_app;
GRANT CREATE, USAGE ON SCHEMA public TO fides_app;
GRANT <table owner> TO fides_app;   -- e.g. GRANT postgres TO fides_app
```

The last two grants are the ones that are easy to leave out and impossible to
skip. This same role applies the policies on every boot, so it needs `CREATE` on
the schema (for the helper function) and ownership of every table (for `ALTER
TABLE … ENABLE ROW LEVEL SECURITY`). Grant only the first three and the server
still refuses to start — with `permission denied for schema public`, and then,
once that is fixed, `must be owner of table tenant_auth_configs`.

The Helm chart already does this — its seed job creates `fides_app` and applies
the policies, and `rls.enabled` has always defaulted to `true`. `docker-compose`
deliberately leaves RLS off, because it connects as `POSTGRES_USER` and enabling
it there would now stop the stack from booting over something unfixable without
a second role.

#### A rolling update can see an empty database

**This is the one to plan for.** The policies are applied at startup, and they
match on a tenant the application sets per request. A pod still running with RLS
*off* does not set it, so once a new pod has applied the policies that old pod
matches nothing: every tenant query returns no rows, and it will not report an
error while doing it.

It only bites where RLS is effective — that is, wherever the connection is not a
superuser and does not hold `BYPASSRLS`. Where the connection is a superuser,
nothing changes, because nothing was ever enforced.

Do not read "not a superuser" as "only the Helm chart". On managed Postgres —
RDS, Cloud SQL, Azure Database — the master user you were most likely already
using is typically *not* a superuser and *does* own the tables. That is exactly
the shape that passes the startup check and applies the policies, so such a
deployment can go from no enforcement to full enforcement on its first boot on
this version, without anyone choosing to turn anything on. If you are on managed
Postgres, check before upgrading:

```sql
SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user;
```

Two `f`s means this section applies to you.

If your deployment has a maintenance window, take it. Otherwise expect a window,
between the first new pod starting and the last old pod stopping, in which the
old pods answer as though the organization has no data.

#### Rolling back needs more than the variable

**Setting `FIDES_RLS_ENABLED=false` on its own is not a rollback, and on a
least-privilege role it is an outage.** The policies live on the tables, not in
the application. The variable only controls whether Fides sets the tenant on
each request — so with it off, a non-superuser connection sets nothing, matches
nothing, and sees no rows at all. That is the same mechanism as the rolling
update above, made permanent.

To actually roll back, do one of:

- **Keep the flag on.** If the concern is a specific bug rather than RLS itself,
  this is almost always the right answer.
- **Set the flag off *and* connect as a superuser again.** Superusers ignore the
  policies, so the deployment behaves as it did before this change — with the
  handlers still scoping every query, which is where isolation actually comes
  from.
- **Set the flag off and drop the policies**, if you want them gone:

  ```sql
  DO $$ DECLARE t text;
  BEGIN
    FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
      EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY', t);
    END LOOP;
  END $$;
  ```

  Note that the next boot with the flag on re-applies them; `schema-rls.sql`
  runs on every start by design, so that it can self-heal an older policy set.
