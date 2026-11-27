---
status: draft
issue: 522
spec: spec/2026-11-27-522-handler-boundaries.md
---

# Plan: Give API and CLI code clear domain boundaries

## Approved design

Move existing route handlers out of `pkg/api/server.go` into domain files for SSO, artifacts, compliance and the assistant. Split CLI integrations and the remaining large `cmd/cli/main.go` by existing subcommand families. Aim for roughly 800 lines per file by responsibility. Keep hand-maintained `pkg/api/swagger.go` as an explicit size exception in this issue. Share drift enrichment between environment list and audit export after #520 establishes query and allowlist semantics. Use JSON encoding for assistant policy fallbacks, including both the no-model and model-error paths.

### Alternatives rejected

Artificially splitting the handwritten spec or generating it during this refactor would add a separate documentation migration. Duplicating the drift helper preserves the existing risk of divergence.

## Steps

Line references are from the reviewed base. Refresh them after dependent changes land.

1. **pkg/api/server.go:120–309, 745–955, 1060–1254, 1430–1656** — After overlapping fixes, move SSO, artifact, compliance and assistant handlers into their existing or new domain files. Preserve route registration and API contracts. Use JSON encoding in both policy fallback branches, preserving each branch's existing control content. Keep `pkg/api/swagger.go` as the approved size exception.
2. **pkg/api/environment_handlers.go:106–207, 209–370** — After #520, reuse its batched enrichment in list and audit paths. Preserve the relevant output shape for each consumer and verify allowlist handling in both views.
3. **cmd/cli/main.go:35–222 and cmd/cli/integrations.go** — Group command functions by existing CLI subcommand domains, including large code that remains in main. Keep roughly the approved 800-line target and avoid changing flags, registration or output as part of moves. Separate the JSON behavior fix in review from mechanical changes.

## Risks

Mechanical moves can alter route wiring or CLI registration if declarations are lost. The drift refactor shares code with #520 and #521. Land targeted correctness work first and isolate JSON behavior changes from moves.

## Tests

Run all Go checks and PostgreSQL integration. Compare registered routes and representative CLI help. Verify assistant fallback output parses with quotes and newlines in both paths and compare list/audit drift for the same environment.

For code changes, run `go build ./...`, `go vet ./...`, `go test ./...` and `gosec -severity medium -confidence high ./...`. With the repository CI PostgreSQL 15 fixture and `FIDES_TEST_DB_DSN` set, run `go test -p 1 ./pkg/db/ ./pkg/api/ ./pkg/events/ ./pkg/servicenow/ -run "Integration|EndToEnd" -v`. Confirm relevant cases ran and record the result.

Run repository Go checks and PostgreSQL integration. Verify route and CLI help parity, identical drift data where the two views overlap, and valid policy JSON for quotes and newlines.

## Rollback

Revert moves and any shared enrichment changes in reverse dependency order. Keep JSON correctness if it can be reverted independently from the structural changes.
