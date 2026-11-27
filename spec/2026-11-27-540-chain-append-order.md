---
status: draft
issue: 540
intent: intent/2026-11-27-540-chain-append-order.md
---

# Spec: Serialize chained writers per trail

## Design

Use a single shared append operation for the existing chained writers. Hold a PostgreSQL transaction-level lock per trail across the head read and row insert. Use the existing request-scoped connection for RLS. Assign the append time within the lock, strictly after the prior ordered chain entry, while preserving the existing time and ID ordering for reads. Preserve ordinary ingestion's atomic optional outbox insert and the existing separate best-effort side effects where applicable.

## Alternatives rejected

A process-only lock misses concurrent Fides replicas. Changing stored hashes or reconstructing historical order would alter existing evidence.

## Risks

A long transaction delays writers to that trail. Keep outbound calls and best-effort postprocessing outside the critical section. Existing invalid chains remain evidence of the problem.

## Verification

Run the #523 16-writer HTTP regression through the public verifier and confirm the count. Test ordinary ingestion with events enabled and disabled, mixed chained writers, RLS, and the Go and PostgreSQL CI checks.
