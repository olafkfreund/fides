---
status: draft
issue: 521
spec: spec/2026-11-27-521-rls-connection-scope.md
---

# Plan: Keep each RLS request on one database connection

## Approved design

Keep the pinning middleware. Add a transaction entry point that begins on the current scoped connection when present and falls back to the pool only for an unscoped request. Route snapshot, settings and framework catalog transactions through it, carrying the transaction querier through subordinate operations. In `pkg/api/server.go`, close artifact rows before supplementary queries, or use the set-based read from #520 if it has landed. In `pkg/db/scope.go`, reset using a short fresh context and invalidate the physical connection via `driver.ErrBadConn` if scope setup or cleanup cannot establish a safe state. Preserve existing transaction-local scoping where it is independently required.

### Alternatives rejected

Increasing MaxOpenConns postpones exhaustion. Starting a transaction spanning every middleware request would change the lifetime of reads and external I/O.

## Steps

Line references are from the reviewed base. Refresh them after dependent changes land.

1. **pkg/db/scope.go:24–77 and pkg/api/auth_middleware.go:161–175** — Add the scoped transaction entry point. Begin on the authenticated request's connection or the pool when unscoped. Keep the current middleware lifetime. Bound cleanup with a fresh context, discard the physical connection on unsafe setup/reset via `driver.ErrBadConn`, and exercise reset failure and cancellation in `pkg/db/scope_cancel_integration_test.go`. Inventory direct pool calls in authenticated tenant handlers. Ensure nested transaction use cannot silently escape scope.
2. **pkg/api/ingest_handlers.go:458–610, pkg/api/settings_handlers.go:134 and pkg/api/framework_catalogs.go:127** — Route the three transactions through the scoped entry point and pass the transaction querier to subordinate calls. Preserve transaction-local GUC setup where required. Close snapshot cursors before further operations.
3. **pkg/api/server.go:798–875 and pkg/api/rls_e2e_test.go:25–110** — Read and close artifact rows before SBOM queries. If #520 has landed first, use its set-based read. Exercise the real RLS request path with MaxOpenConns=2, eight simultaneous requests, two tenants and a restricted role. Cover API success, rollback and tenant isolation.

## Risks

Scope cleanup after cancellation or a reset error must prevent reusing a connection with residual tenant state. Inventory direct pool use in authenticated tenant routes to catch missed paths.

## Tests

Run `go test ./pkg/db ./pkg/api` with and without the CI PostgreSQL configuration as applicable. Repeat the bounded concurrency case and confirm settings, framework import and populated SBOM reads.

Extend `pkg/api/snapshot_rls_integration_test.go` so the fixture checks real concurrent scoped snapshot writes.

For code changes, run `go build ./...`, `go vet ./...`, `go test ./...` and `gosec -severity medium -confidence high ./...`. With the repository CI PostgreSQL 15 fixture and `FIDES_TEST_DB_DSN` set, run `go test -p 1 ./pkg/db/ ./pkg/api/ ./pkg/events/ ./pkg/servicenow/ -run "Integration|EndToEnd" -v`. Confirm relevant cases ran and record the result.

Extend the scoped connection tests for cancellation and reset failure. With RLS active under a restricted role and a pool of two connections, send eight concurrent scoped snapshot writes across two orgs and verify completion, rollback behavior and tenant isolation. Exercise settings, catalog import and artifact reads.

## Rollback

Revert the request and DB helper changes together. This has no migration. If #519 already depends on the helper, coordinate its rollback first or retain the compatible helper.
