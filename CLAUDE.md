# CLAUDE.md — Fides project context

## Frontend / Portal UI — IMPORTANT (CORRECTED 2026-07-28)

> **⚠️ CORRECTION — everything below dated 2026-07-01 is STALE.** The portal
> frontend **IS source-owned in this repo at `portal/`** (Next.js 16 / React 19 +
> Tailwind v4). A CUTOVER (see `Dockerfile.server`) replaced the old externally
> built compiled SPA: the Dockerfile builds `portal/` and its `out/` **overwrites
> `./web/`**, which the Go `http.FileServer` serves at `/`.
>
> - **To change ANY portal UI, edit `portal/src/app/…` (real TSX), then
>   `cd portal && npm run build`.** Frontpage/dashboard = `portal/src/app/(portal)/page.tsx`;
>   other pages under `(portal)/` (settings, environments, controls, attestations,
>   flows, policies, ai-audits, artifacts, telemetry, help). Components in
>   `portal/src/components/`; API client `portal/src/lib/api.ts` (`apiGet`/`apiPost`,
>   same-origin cookie auth). Theme tokens in `portal/src/app/globals.css` — brand
>   `--primary` is **gold**; use `text-primary`/`border-border`/`bg-card`/
>   `text-muted-foreground`; light+dark via next-themes. **Next 16 has breaking
>   changes — read `portal/AGENTS.md` / `node_modules/next/dist/docs/` first.**
> - **Do NOT** build Go-served `go:embed` HTML pages for UI, and do NOT edit
>   `web/admin-tab.js` — that iframe-injection approach is dead (admin-tab.js is
>   404 live). The Go-served `/servicenow`, `/admin`, `/evidence`, `/console`
>   pages are orphaned and being removed. **Their `_ui.go` files also hold API
>   handlers the portal still calls** (`handleServiceNowEvents` →
>   `/api/v1/tenant/servicenow/events`, `handleConsoleSummary` →
>   `/api/v1/console/summary`) — keep those. The `http.FileServer` on `./web` STAYS.
>
> Historical (stale) notes follow, kept for context only:

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
- **Do NOT hand-edit the minified `_next` chunks** — doing so previously corrupted
  the portal (a broken chunk caused `SyntaxError` → blank page). CI guards this
  via a `node --check` step on every chunk.
- **The supported way to add UI is a Go-served page** embedded in the server
  binary via `go:embed` and routed in `pkg/api/server.go`, authenticated by the
  session cookie. Examples: `/servicenow` and the unified admin console `/admin`
  (`pkg/api/admin_ui.go` + `pkg/api/assets/admin.html`).
- **You CAN add a tab to the existing React Settings page** (proven working) via
  a Go-served **enhancement script**: `web/admin-tab.js` (loaded from
  `web/index.html`, which we control) injects an "Integrations" tab into the
  Settings tab strip and renders `/admin` in a same-origin iframe. It clones the
  existing tab classes, anchors on the "Settings Management" heading + the
  "Infrastructure Settings" button, and re-injects on a 700ms poll. This required
  relaxing the global `X-Frame-Options` to `SAMEORIGIN` and CSP `frame-ancestors`
  to `'self'` in `securityHeaders` so the app can frame its own pages.

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
