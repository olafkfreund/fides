---
status: draft
issue: 523
spec: spec/2026-11-27-523-critical-regressions.md
---

# Plan: Cover critical request and concurrency paths

## Approved design

Build on `pkg/api/*_integration_test.go`, `pkg/db/*_integration_test.go`, `pkg/events/events_integration_test.go` and `.github/workflows/go-build.yml`. Check actual mutating API routes over tenant role and credential combinations using isolated fixtures. Exercise concurrent appends to a single trail and verify the resulting chain. Assert outbound policy consistently rejects disallowed redirects and address classes with injected test DNS and transports. Add dispatcher lease tests with #519 and stdio MCP contract tests with #517, keeping each test at the layer that owns the behavior. Keep assertions tied to the intended behavior if they uncover a production defect and link the corrective issue before marking coverage complete.

### Alternatives rejected

A single giant PostgreSQL test would mix independent failure modes and require a database for client transport and codec checks.

## Steps

Line references are from the reviewed base. Refresh them after dependent changes land.

1. **pkg/api/server.go:120–310, pkg/api/auth_middleware.go:75–177** — Inventory mutating routes and credential types, then test actual route authorization with isolated tenant fixtures. Assert authenticated allowed and denied outcomes and legacy/unauthenticated behavior where applicable. Verify denied calls cannot mutate rows. Explicitly classify public signed webhook routes so their authorization checks remain represented.
2. **pkg/api/attestation_chain_integration_test.go and pkg/events/events_integration_test.go** — Use deterministic barriers in real PostgreSQL fixtures for concurrent ordinary appends and #519 lease reclaim. Assert count and chain verification, plus ownership and independent sink retries. If the test exposes a production defect, link and resolve the corrective issue before claiming complete coverage.
3. **pkg/webhooks/webhook_test.go, pkg/tsa/tsa_test.go, pkg/servicenow/client.go, other outbound integrations and cmd/mcp/main.go:515–525** — Test outbound policy using injected resolver or transport fixtures and local test HTTP endpoints. Use #517's stdio request cases for success and errors. Extend `.github/workflows/go-build.yml:195–225` only where the existing jobs would skip required cases.

## Risks

An authorization fixture that exits at input validation before reaching the authorization distinction can falsely pass. Concurrency tests need deterministic barriers or timestamps and isolated data. Use host-local fixtures only.

## Tests

Run `go test ./...` and the PostgreSQL CI jobs with `FIDES_TEST_DB_DSN` configured. Confirm the named cases actually ran. Include deterministic authorization, outbound defensive checks, chain validity and MCP transport behavior.

Ensure DB-backed MCP cases are in an invoked job, since the existing PostgreSQL command targets db, api, events and servicenow only.

For code changes, run `go build ./...`, `go vet ./...`, `go test ./...` and `gosec -severity medium -confidence high ./...`. With the repository CI PostgreSQL 15 fixture and `FIDES_TEST_DB_DSN` set, run `go test -p 1 ./pkg/db/ ./pkg/api/ ./pkg/events/ ./pkg/servicenow/ -run "Integration|EndToEnd" -v`. Confirm relevant cases ran and record the result.

Run the named suites under the existing CI unit and PostgreSQL jobs. Verify allowed and denied route cases, tenant separation, final chain validity, outbound policy, competing worker ownership, and MCP success and HTTP-error handling.

## Rollback

Revert only this issue's fixtures or CI wiring when necessary. Preserve coverage introduced and owned by #517 or #519.
