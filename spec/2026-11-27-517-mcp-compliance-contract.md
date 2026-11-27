---
status: approved
issue: 517
intent: intent/2026-11-27-517-mcp-compliance-contract.md
---

# Spec: Align the MCP and CLI compliance contract

## Design

In `cmd/mcp/main.go`, translate the existing public `artifact_sha256` argument to the server's `sha256` query key. Keep the advertised optional `is_compliant` argument with a description marking it deprecated and ignored. Stop sending it to the API. In `cmd/cli/main.go`, check HTTP status before using the response and report transport, HTTP and invalid verdict failures as exit 1. Keep exit 2 for a valid non-compliant result. Reject a non-empty `assert --policy` with a clear unsupported message and update its documentation. Reject non-empty `policy` on the HTTP endpoint with a clear 400 to prevent the same silent error for direct callers. Preserve the existing digest-wide evaluation when no selector is supplied.

## Alternatives rejected

Implementing a named-policy endpoint here would require a policy selection contract and persistence semantics. Accepting a client verdict would bypass the server's policy calculation.

## Risks

Pipelines that passed an ignored selector will fail visibly until corrected. The MCP tool argument name is a separate contract from the HTTP key.

## Verification

Exercise MCP against the actual server route with a seeded fixture, including the encoded digest and attestation body. Test CLI exit 0 for compliance, 2 for a valid negative verdict, and 1 for HTTP failures, invalid responses and an unsupported selector.
