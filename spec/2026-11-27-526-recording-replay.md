---
status: approved
issue: 526
intent: intent/2026-11-27-526-recording-replay.md
---

# Spec: Queue evidence during recording outages

## Design

Add opt-in fail-open handling to the trail creation, artifact report and attestation recording entry points in `cmd/cli/main.go` and their specialized recording paths. Use a durable, permission-restricted spool with 0700 directories and 0600 entries that atomically saves the request and attachment bytes before returning success, emits a warning, and binds each entry to an endpoint and tenant credential identity without persisting tokens. Store stable request IDs and dependency links. Support an offline trail reference for chained CLI work and resolve it to the resulting server ID on replay. Replay oldest ready entries first, use current credentials for the bound endpoint, retain entries until confirmed, and use server-side tenant-scoped idempotency for ambiguous transport or selected retryable server errors, rejecting conflicting reuse. Keep gating fail-closed by default. Keep gate overrides out of this release. A future explicit override requires its own durable evidence design.

## Alternatives rejected

Returning success on failure without durable spooling drops compliance evidence. A client-only retry cannot resolve an ambiguous successful write.

## Risks

CI runners with ephemeral disks can lose spooled evidence. The spool can contain sensitive evidence and can fill up. Document retention, artifact mounting and the exact commands and statuses eligible for spooling.

## Verification

Exercise network failure, retryable 5xx, final 4xx, permission and disk failures, attachments, dependent records, and interruption after server commit. Verify replay deduplicates and concurrent replays cannot delete unconfirmed entries. Check that an unavailable server still fails a default gate.
