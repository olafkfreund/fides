---
status: approved
issue: 516
intent: intent/2026-11-27-516-db-query-panics.md
---

# Spec: Handle database query failures without panicking

## Design

In `pkg/events/dispatcher.go`, return the wrapped claim error before touching rows. Keep the cursor closed on every scan or iteration exit and before notifying sinks. In `pkg/api/environment_handlers.go`, return the existing generic HTTP 500 when the snapshot-artifact query fails and release each cursor before querying further. In `pkg/api/server.go`, check errors before using rows in the two deterministic AI chat commands. Preserve successful responses.

## Alternatives rejected

Keeping environment enrichment best-effort could return a successful but incomplete compliance view. A handler-wide defer inside the environment loop would keep cursors open for later queries.

## Risks

A prematurely retained cursor can block a follow-up query on an RLS-scoped connection. Error responses should use `internalError` to keep database details out of API responses.

## Verification

Use the existing PostgreSQL driver with a pre-cancelled context to verify that `DispatchBatch` returns zero and wraps the query error without a database connection. Run `go test ./pkg/events ./pkg/api` and applicable PostgreSQL integration tests.
