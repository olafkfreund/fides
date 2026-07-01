# Fides Portal (Next.js source)

A from-scratch, **source-owned** rebuild of the Fides portal (the compiled SPA in
`../web/` has no source). It is a **Next.js 16 static export** — `next build`
emits static files into `out/`, which the Go server serves from `../web/`
(single-binary deploy, unchanged). All data is fetched client-side from the
same-origin Fides REST API.

## Status: Phase 1 (scaffold)

Working skeleton to validate the approach:
- Next.js 16 (App Router) + TypeScript + Tailwind, `output: "export"`.
- `src/lib/api.ts` — same-origin API client (session-cookie auth).
- **Login** (`/login`) wired to `POST /api/v1/auth/local-login`.
- App **Shell** with sidebar nav + a client-side auth guard (redirects to `/login`).
- **Overview** (`/`) — real DORA metrics + flow count.
- **Settings** (`/settings`) — ServiceNow config (real `GET`/`POST /api/v1/tenant/servicenow`).
- Other screens are marked "coming soon" and built incrementally.

## Develop

```bash
npm install
npm run dev        # http://localhost:3000
# point at the live API for dev (server must allow CORS w/ credentials):
NEXT_PUBLIC_API_BASE=https://fides.example.com npm run dev
```

## Build & cut over

```bash
npm run build      # -> ./out (static export)
```

When at parity, replace the served assets: copy `out/` into `../web/`. Until
then the existing portal is untouched. Nav screens are added incrementally
(each = a page under `src/app/(portal)/` using the API client).

> Note: this dir also has an `AGENTS.md` — a Next 16 breaking-changes reminder
> from create-next-app.
