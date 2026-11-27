---
status: approved
issue: 516
spec: spec/2026-11-27-516-db-query-panics.md
---

# Plan: Handle database query failures without panicking

## Approved design

In `pkg/events/dispatcher.go`, return the wrapped claim error before touching rows. Keep the cursor closed on every scan or iteration exit and before notifying sinks. In `pkg/api/environment_handlers.go`, return the existing generic HTTP 500 when the snapshot-artifact query fails and release each cursor before querying further. In `pkg/api/server.go`, check errors before using rows in the two deterministic AI chat commands. Preserve successful responses.

### Alternatives rejected

Keeping environment enrichment best-effort could return a successful but incomplete compliance view. A handler-wide defer inside the environment loop would keep cursors open for later queries.

## Steps

Line references are from the reviewed base. Refresh them after dependent changes land.

1. **pkg/events/dispatcher.go:99–129** — Guard the claim error before touching rows. Close on scan and iteration exits and before the sink loop. In `pkg/events/dispatcher_test.go`, add a pre-cancelled-context regression using the existing driver and a lazily opened test DB handle. Verify zero processed and `errors.Is(err, context.Canceled)` without a running database.
2. **pkg/api/environment_handlers.go:143–183 and pkg/api/server.go:1611–1656** — Return the generic internal error from the snapshot-artifact query and both deterministic chat query branches before writing success. Close each environment cursor before enrichments on the same scoped connection. Check baseline success behavior and failures. A handler-wide defer inside the environment loop would extend the cursor lifetime.

## Risks

A prematurely retained cursor can block a follow-up query on an RLS-scoped connection. Error responses should use `internalError` to keep database details out of API responses.

## Tests

Run `go test ./pkg/events ./pkg/api`. With the CI PostgreSQL configuration, run matching dispatcher and scoped API tests and check successful response shape.

In scoped fixtures, exercise a follow-up query after cleanup to verify the connection remains usable.

For code changes, run `go build ./...`, `go vet ./...`, `go test ./...` and `gosec -severity medium -confidence high ./...`. With the repository CI PostgreSQL 15 fixture and `FIDES_TEST_DB_DSN` set, run `go test -p 1 ./pkg/db/ ./pkg/api/ ./pkg/events/ ./pkg/servicenow/ -run "Integration|EndToEnd" -v`. Confirm relevant cases ran and record the result.

Use the existing PostgreSQL driver with a pre-cancelled context to verify that `DispatchBatch` returns zero and wraps the query error without a database connection. Run `go test ./pkg/events ./pkg/api` and applicable PostgreSQL integration tests.

## Rollback

Revert the issue's code commit if required. There are no storage changes.
