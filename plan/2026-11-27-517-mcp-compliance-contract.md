---
status: draft
issue: 517
spec: spec/2026-11-27-517-mcp-compliance-contract.md
---

# Plan: Align the MCP and CLI compliance contract

## Approved design

In `cmd/mcp/main.go`, translate the existing public `artifact_sha256` argument to the server's `sha256` query key. Keep the advertised optional `is_compliant` argument with a description marking it deprecated and ignored. Stop sending it to the API. In `cmd/cli/main.go`, check HTTP status before using the response and report transport, HTTP and invalid verdict failures as exit 1. Keep exit 2 for a valid non-compliant result. Reject a non-empty `assert --policy` with a clear unsupported message and update its documentation. Reject non-empty `policy` on the HTTP endpoint with a clear 400 to prevent the same silent error for direct callers. Preserve the existing digest-wide evaluation when no selector is supplied.

### Alternatives rejected

Implementing a named-policy endpoint here would require a policy selection contract and persistence semantics. Accepting a client verdict would bypass the server's policy calculation.

## Steps

Line references are from the reviewed base. Refresh them after dependent changes land.

1. **cmd/mcp/main.go:515–525, 618–632 and tool definitions near line 376** — Keep `artifact_sha256` in the public input and send `sha256` only as the API query key. Mark `is_compliant` optional, deprecated and ignored, and omit it from writes. Verify the call against the real `pkg/api/server.go:886` route with seeded tenant data and verify the issued attestation body. Server-derived verdicts remain authoritative.
2. **cmd/cli/main.go:455–516 and pkg/api/server.go:886–904** — Reject a non-empty policy selector explicitly in CLI and at the HTTP endpoint. Inspect status before decoding a verdict and require a valid boolean field. Use the existing exit-code conventions: 0 for compliant, 2 for valid negative, 1 for unsupported selector or request/response failure.
3. **docs/cli-reference.md, web/cli-reference.md, docs/mcp-server.md and web/mcp-server.md** — Search tracked examples for assert with --policy, including CLI help, docs/architecture_proposal.md, first-run.md, getting_started.md, scanner-integration.md, user-stories.md and matching Markdown copies. Update runnable examples and document the selector rejection. Keep matching portal-served guides in sync.

## Risks

Pipelines that passed an ignored selector will fail visibly until corrected. The MCP tool argument name is a separate contract from the HTTP key.

## Tests

Run `go test ./cmd/cli ./cmd/mcp ./pkg/api` and the PostgreSQL-backed MCP/API route case. Verify the CLI exits and distinct HTTP/parse errors with fixtures.

For code changes, run `go build ./...`, `go vet ./...`, `go test ./...` and `gosec -severity medium -confidence high ./...`. With the repository CI PostgreSQL 15 fixture and `FIDES_TEST_DB_DSN` set, run `go test -p 1 ./pkg/db/ ./pkg/api/ ./pkg/events/ ./pkg/servicenow/ -run "Integration|EndToEnd" -v`. Confirm relevant cases ran and record the result.

Exercise MCP against the actual server route with a seeded fixture, including the encoded digest and attestation body. Test CLI exit 0 for compliance, 2 for a valid negative verdict, and 1 for HTTP failures, invalid responses and an unsupported selector.

## Rollback

Revert client and API changes together if necessary. There are no storage changes. The previous version will have the known request-key and selector defects.
