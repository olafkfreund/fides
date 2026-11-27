---
status: draft
issue: 540
spec: spec/2026-11-27-540-chain-append-order.md
coders:
  1: codex # Transactional append ordering is shared correctness logic.
  2: codex # Move the existing chained writers through that operation.
reviewers:
  - agy # Review the draft and the final diff against transaction and RLS requirements.
---

# Plan: Serialize chained attestation appends

Use a PostgreSQL transaction-scoped lock per trail. Keep chain read order, stored histories, hash format, RLS, and outbox semantics.

## Steps

1. **`pkg/api/attestation_chain.go:14`** — Add a shared append operation that begins a transaction with `db.BeginTx`, locks the trail before reading the predecessor, computes the existing content hash, and supplies a timestamp strictly greater than the predecessor's. Use microsecond precision and the database clock. Return after commit and roll back any insert error. Keep downstream network and object-store work outside the lock. Check repeated concurrent appends with the public verifier.
2. **`pkg/api/ingest_handlers.go:220`, `flags.go:103`, `sod.go:194`, `branch_protection.go:81`, `servicenow_handlers.go:226`, `attest_fetch.go:144`** — Route each existing chained insert through the operation, retaining field values and postprocessing. Include the optional ordinary ingestion outbox enqueue in the transaction. Preserve preexisting best-effort behavior in the other writers. Check ordinary ingestion with events enabled and disabled, a mixed-writer trail, and RLS.
3. **`pkg/api/attestation_chain_integration_test.go:23`** — Verify historical verifier behavior and the #523 regression on local PostgreSQL 15. Run the standard Go and PostgreSQL gates and review the complete diff against this plan. Link #523 and #540 in the PR.

## Tests

Run the 16-writer HTTP test repeatedly with `-race`; assert all counts and public verify-chain validity. Run Go build, vet, unit and race tests, golangci-lint, gosec, and the PostgreSQL integration selection with Go 1.26.11.

## Rollback

Revert the code through its issue branch. Existing evidence remains readable without a schema change.
