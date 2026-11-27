---
status: approved
issue: 521
intent: intent/2026-11-27-521-rls-connection-scope.md
---

# Spec: Keep each RLS request on one database connection

## Design

Keep the pinning middleware. Add a transaction entry point that begins on the current scoped connection when present and falls back to the pool only for an unscoped request. Route snapshot, settings and framework catalog transactions through it, carrying the transaction querier through subordinate operations. In `pkg/api/server.go`, close artifact rows before supplementary queries, or use the set-based read from #520 if it has landed. In `pkg/db/scope.go`, reset using a short fresh context and invalidate the physical connection via `driver.ErrBadConn` if scope setup or cleanup cannot establish a safe state. Preserve existing transaction-local scoping where it is independently required.

## Alternatives rejected

Increasing MaxOpenConns postpones exhaustion. Starting a transaction spanning every middleware request would change the lifetime of reads and external I/O.

## Risks

Scope cleanup after cancellation or a reset error must prevent reusing a connection with residual tenant state. Inventory direct pool use in authenticated tenant routes to catch missed paths.

## Verification

Extend the scoped connection tests for cancellation and reset failure. With RLS active under a restricted role and a pool of two connections, send eight concurrent scoped snapshot writes across two orgs and verify completion, rollback behavior and tenant isolation. Exercise settings, catalog import and artifact reads.
