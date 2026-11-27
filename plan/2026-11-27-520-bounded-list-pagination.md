---
status: draft
issue: 520
spec: spec/2026-11-27-520-bounded-list-pagination.md
---

# Plan: Bound API lists and environment enrichment

## Approved design

Inventory collection GET routes from `pkg/api/server.go` and their clients. Preserve JSON arrays and add a standard `Link: <…>; rel="next"` header. Apply a default page size of 100 and a maximum of 500. Use ordered keyset queries with a unique final tie-breaker, fetching one extra row. Validate cursor version and route, tenant and filter scope and always apply current authenticated tenant filters. Update maintained portal, CLI and MCP callers to follow same-origin next links, with response-size limits where the client needs only a subset. In `pkg/api/environment_handlers.go`, batch latest snapshots, running artifacts, allowlists and trail compliance for the selected environments with a constant query count. Batch artifact summary rows in `pkg/api/server.go` and surface query errors.

### Alternatives rejected

An envelope would break JSON decoding in array consumers. An offset can skip or repeat rows as the collection changes.

## Steps

Line references are from the reviewed base. Refresh them after dependent changes land.

1. **pkg/api/server.go:120–310, 791–875, 945–975; pkg/api/trails_list.go** — Inventory scope by collection GET route and callers, including already capped list routes. Review search.go, controls.go, policies.go, allowlist.go, settings_handlers.go, services.go, approvals.go and service_accounts.go as well as handlers named List. Add the smallest shared pagination contract for an array plus `Link` next relation. Validate limits and a versioned cursor against route, tenant and relevant filters. Add per-query stable unique ordering, one extra fetched row, and use keyset conditions over the same order. Default to 100 and cap at 500. Preserve tenant predicates, even for a valid cursor.
2. **pkg/api/environment_handlers.go:106–206 and pkg/api/shadow_classify.go** — Page base environments before batch-loading latest snapshots, artifacts, allowlists and compliance. Copy digest allowlist semantics from ingestion. Batch artifact summaries in `pkg/api/server.go:791–875` and propagate errors. Coordinate with #521 so query cursors close before another request on a pinned connection.
3. **portal/src/lib/api.ts, cmd/cli/main.go and cmd/mcp/main.go** — Trace all maintained callers of the inventoried routes and follow same-origin next links, keeping pagination visible for large UI lists and allowing caller-specific bounded reads. Update the hand-maintained Swagger spec and portal-facing Markdown copies to explain that unchanged external callers receive the first page. Do not modify built portal assets.

## Risks

External clients that ignore Link get the first page of newly bounded lists. Document that behavior and the release transition. Use stable sort order and retain explicit filters such as environment identity, because an opaque cursor is not authorization. The keyset provides ordering across pages, with ordinary visibility of collection changes between requests.

## Tests

Run pagination tests for limits, empty and terminal pages, tie breakers, invalid filter/tenant/cursor, and at least two client pages. Verify environment allowlist parity and a constant query count at different page sizes. Run Go and PostgreSQL tests plus the repo's portal build.

For code changes, run `go build ./...`, `go vet ./...`, `go test ./...` and `gosec -severity medium -confidence high ./...`. With the repository CI PostgreSQL 15 fixture and `FIDES_TEST_DB_DSN` set, run `go test -p 1 ./pkg/db/ ./pkg/api/ ./pkg/events/ ./pkg/servicenow/ -run "Integration|EndToEnd" -v`. Confirm relevant cases ran and record the result.

For portal changes, read `portal/AGENTS.md` and the relevant installed Next.js guide. Run `NODE_ENV=development npm ci --include=dev` in `portal/`, then unset `NODE_ENV` and run `npm run build`. Edit portal source files and keep the generated pages untouched.

Exercise empty/final pages, limit validation, duplicate sort keys, invalid or mismatched cursors, org boundaries, and all maintained consumers. Assert a constant query count as environment count grows and verify allowlist parity with ingest.

## Rollback

Revert server cap and client changes together, or restore the original client-facing contract in a compatible deployment. Document the transition if an external caller has already adopted cursors.
