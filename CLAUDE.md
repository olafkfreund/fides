# CLAUDE.md — Fides project context

## Frontend / Portal UI — read this before touching any UI

The portal frontend **is source-owned in this repo at `portal/`** (Next.js 16 /
React 19 + Tailwind v4). `Dockerfile.server` builds `portal/` and its `out/`
**overwrites `./web/`**, which the Go `http.FileServer` serves at `/`. So
everything under `web/` is BUILD OUTPUT — never edit it by hand, your change is
overwritten on the next build.

**To change any portal UI:** edit `portal/src/app/…` (real TSX), then
`cd portal && npm run build`.

- Frontpage/dashboard = `portal/src/app/(portal)/page.tsx`; other pages under
  `(portal)/`: ai-audits, artifacts, attestations, controls, environments,
  exceptions, flows, help, policies, risks, sdlc, services, settings, telemetry.
- Components in `portal/src/components/`; API client `portal/src/lib/api.ts`
  (`apiGet`/`apiPost`, same-origin cookie auth).
- Theme tokens in `portal/src/app/globals.css` — brand `--primary` is **gold**;
  use `text-primary` / `border-border` / `bg-card` / `text-muted-foreground`.
  Light+dark via next-themes.
- **Next 16 has breaking changes — read `portal/AGENTS.md` first.**
- Local build is two commands with **different** `NODE_ENV`, and getting this
  wrong wastes an afternoon in both directions:

  ```bash
  cd portal
  NODE_ENV=development npm ci --include=dev   # install: prod NODE_ENV silently omits devDeps
  unset NODE_ENV && npm run build             # build: NODE_ENV=development breaks it
  ```

  A prod `NODE_ENV` at install time omits devDependencies (`@tailwindcss/postcss`,
  `typescript`, …) and `npm` still says "up to date". But leaving
  `NODE_ENV=development` set for the build fails every page's prerender with
  `Cannot read properties of null (reading 'useContext')` from next-themes
  against Next 16's vendored SSR React — and the error names whichever page it
  reached first, so it reads like that one page is broken. It is not; the
  variable is. `Dockerfile.server` runs a plain `npm run build`, which is why CI
  never sees this.

### Do NOT add Go-served `go:embed` HTML pages

That pattern is **gone**, not deprecated — as of the ponytail cleanup there is no
`pkg/api/assets/` directory and no HTML page handler left in the repo. Earlier
revisions of this file recommended it and pointed at `pkg/api/admin_ui.go`,
`pkg/api/assets/admin.html` and `web/admin-tab.js`; **all three no longer exist.**
The `web/admin-tab.js` iframe-injection trick is dead too.

The two surviving `_ui.go` files are misnamed leftovers holding **only API
handlers the portal still calls** — keep them, they serve no HTML:

| file | handlers | routes |
|---|---|---|
| `pkg/api/servicenow_ui.go` | `handleServiceNowEvents` | `GET /api/v1/tenant/servicenow/events` |
| `pkg/api/console_ui.go` | `handleConsoleSummary`, `handleConsoleStream` | `GET /api/v1/console/summary`, `GET /api/v1/console/stream` |

The `http.FileServer` on `./web` STAYS — it is how the built portal is served.

## Architecture quick map

- **Go module `fides`**, Go 1.26. Multi-tenant Postgres (RLS-capable via
  `app.current_org`).
- `cmd/server` — API server (`pkg/api`). Applies embedded migrations on boot
  (`pkg/db/migrate.go` + `pkg/db/migrations/*.sql`; `0001_init.sql` is kept
  byte-identical to root `schema.sql`, enforced by a unit test).
- `cmd/cli` (`fides`) — pipeline + config CLI. Incl. `flow list|trails|artifacts`,
  `policy create|delete|generate` (LLM-drafted rules) + env `policy add|list|check`,
  `metrics [--days N] | deployment-frequency [--weeks N]`, `control`, `env verify`, etc.
- `cmd/mcp` (`fides-mcp`) — MCP server for AI tools (Claude Code, Cursor, Claude Desktop):
  15 tools (list_flows/environments/policies, check_compliance, search_artifacts,
  search_attestations, get_controls_coverage, get_deployment_frequency, ServiceNow +
  provenance recording) **and the docs as MCP resources** (`fides://docs/*`). Shipped in
  the image at `/usr/local/bin/fides-mcp`; guide `docs/mcp-server.md`. `cmd/mcp-sensor` —
  the in-cluster stdio sensor used by environment runtime compliance checks.
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
- Docs: GitHub Pages is Jekyll from root + `docs/*.md` + `_config.yml`. Guides
  live in `docs/` — only `README.md`, `index.md`, `CLAUDE.md`, `CONTRIBUTING.md`
  stay at repo root. Portal docs are the `web/*.md` files served by the Go
  server. Keep the `docs/` and `web/` copies in sync.
