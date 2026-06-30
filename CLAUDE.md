# CLAUDE.md — Fides project context

## Frontend / Portal UI — IMPORTANT (verified 2026-07-01)

**The portal (React/Next.js SPA) source is NOT in this repo and never was.**
This was verified three ways:
1. Working tree: no `.tsx/.jsx/.ts/package.json/next.config/tsconfig` anywhere.
2. Source maps: the only `.map` (`web/_next/static/chunks/a6dad97d9634a72d.js.map`)
   covers a Next.js polyfill, not the app. The app chunk has no source map.
3. Full git history (`git log --all --full-history --diff-filter=A`): **zero**
   source files ever committed. The first `web/` commit (`2e99ade`) added the
   already-compiled `_next` chunks.

The SPA was built externally (by "Antigravity") and **only the static export was
committed** to `web/`. There is no other repo for it. **Do not ask for the
source again** — it does not exist here.

### Consequences for UI work
- The compiled SPA is served by the Go `http.FileServer` from `./web`. The
  Settings page tabs ("Infrastructure Settings", "User Directory & Group
  Mappings") live inside the minified `web/_next/static/chunks/7c90213a0cbc24b6.js`.
- **You CANNOT add a new React tab** to that Settings page without the SPA source.
- **Do NOT hand-edit the minified `_next` chunks** — doing so previously corrupted
  the portal (a broken chunk caused `SyntaxError` → blank page). CI guards this
  via a `node --check` step on every chunk.
- **The supported way to add UI is a Go-served page** embedded in the server
  binary via `go:embed` and routed in `pkg/api/server.go`, authenticated by the
  session cookie. Example: the ServiceNow admin UI.

### ServiceNow admin UI (the worked example of the pattern)
- Page: `GET /servicenow` → `pkg/api/servicenow_ui.go` (`handleServiceNowAdminPage`),
  HTML embedded from `pkg/api/assets/servicenow.html`.
- Backing API: `GET /api/v1/tenant/servicenow/events` (monitor) + the existing
  `/api/v1/tenant/servicenow`, `/api/v1/servicenow/*` endpoints.
- Live at `https://fides.13.134.88.9.nip.io/servicenow`.

## Architecture quick map
- **Go module `fides`**, Go 1.26. Multi-tenant Postgres (RLS-capable via
  `app.current_org`).
- `cmd/server` — API server (`pkg/api`). Applies embedded migrations on boot
  (`pkg/db/migrate.go` + `pkg/db/migrations/*.sql`; `0001_init.sql` is kept
  byte-identical to root `schema.sql`, enforced by a unit test).
- `cmd/cli` (`fides`) — pipeline + config CLI. `cmd/mcp` / `cmd/mcp-sensor` — MCP.
- Event/outbox dispatcher (`pkg/events`, gated by `FIDES_EVENTS_ENABLED`) drives
  sinks: webhooks, GitHub/GitLab commit-status, ServiceNow ITOM+CMDB, Slack.
- Integrations: `pkg/servicenow`, `pkg/slack`, `pkg/gitstatus`, `pkg/webhooks`,
  `pkg/inbound`, `pkg/admission`. Secrets via `pkg/vault` (`SECRETS_PROVIDER=aws`
  uses AWS Secrets Manager through IRSA).

## Workflow rules (from the user)
- Small, non-breaking PRs. Before every merge: `go build ./...`, `go vet ./...`,
  `go test ./...`, gosec (`-severity medium -confidence high`, blocking), and the
  Postgres integration tests (`FIDES_TEST_DB_DSN`, via a `postgres:15-alpine`
  Docker container).
- Deploy target: EKS `sarc-aws` (eu-west-2, account 796973489124), namespace
  `fides`; AWS profile `Synechron`. CI deploys via GitHub OIDC.
- Docs: GitHub Pages is Jekyll from root `*.md` + `_config.yml`; portal docs are
  the `web/*.md` files served by the Go server. Keep them in sync.

## Roadmap
GitHub epic **#60** (ServiceNow UI + Kosli parity). Remaining: **#84**
(controls/coverage framework + Terraform provider).
