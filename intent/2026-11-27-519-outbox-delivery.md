---
status: approved
issue: 519
author: olafkfreund
---

# Intent: Make outbox delivery reliable across retries

## Problem

Domain changes can commit before a failed enqueue. Retrying an event repeats delivery to sinks that already succeeded, and an expired claim allows another worker to process the event while the old worker can still update it.

## Proposed outcome

Events and their domain writes commit together. A failing sink can retry independently, stale workers cannot update a newer claim, and sends have bounded time and retry backoff. PostgreSQL tests cover transaction rollback, claim expiry, and a healthy sink paired with a failing one.

## Affected users and systems

Attestation and snapshot ingestion, integration workers, and configured sinks.

## Constraints

Coordinate with #521 on request transactions and #523 on integration coverage. Preserve pending events through migration. External effects across lost acknowledgments require a downstream idempotency contract.

## Open questions

Which other producers join this change, and which destinations support idempotency across retries?
