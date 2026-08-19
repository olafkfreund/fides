# Upgrading Fides

Behaviour changes that alter what Fides *does* rather than what it offers — the
kind that look like a regression if you meet them without warning. New features
are not listed here; the release notes cover those.

Fides is `v0.x`. Anything may change, and this document is where the changes
that can bite an existing deployment get written down.

## Unreleased

### The TSA host must be one you named

`POST /api/v1/trails/{id}/anchor` accepts a `tsa_url` in its body. It now has to
name a host the server was configured with:

- the host of **`FIDES_TSA_URL`**, always; or
- any host listed in the new **`FIDES_TSA_ALLOWED_HOSTS`** (comma-separated).

**Nothing to do if callers rely on the server's configured TSA** — that host is
permitted automatically, which is the common case and the reason the allowlist
is built from configuration rather than shipped as a list here.

**If callers pass their own `tsa_url`, list those hosts** or the request is
refused with a message naming the variable to add.

#### Why this is not just the dial guard again

The dial guard added earlier stops a timestamp request landing on an internal
address however the name resolves. It does not stop a caller pointing Fides at a
host *they* control on the public internet — and the request carries a trail's
chain-head hash, over a connection carrying whatever an operator put in front of
it. `tsa_url` arrives in a request body, so the destination was attacker-chosen
unless something said otherwise. This is that something.

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
CREATE ROLE fides_app LOGIN PASSWORD '…';
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fides_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO fides_app;
```

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

It only bites where RLS is effective — a non-superuser role, which today means
the Helm chart. Where the connection is a superuser, nothing changes because
nothing was ever enforced.

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
