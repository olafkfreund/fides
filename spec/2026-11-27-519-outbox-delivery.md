---
status: draft
issue: 519
intent: intent/2026-11-27-519-outbox-delivery.md
---

# Spec: Make outbox delivery reliable across retries

## Design

Use the scoped transaction entry point from #521 so attestation and snapshot domain writes enqueue required events before commit whenever events are enabled. Inventory other producers and retain their current semantics in this issue. In `pkg/events` and a new migration, track state per event and stable configured sink identity. Freeze the fan-out set at first scheduling, initialize existing actionable events once, and preserve terminal history. Claim each delivery immediately before starting it with a lease token and check it on every result update. Budget attempts with a per-send context of 30 seconds under the existing 60-second default lease, scaling down the send timeout if a deployment uses a shorter lease and jitter retry scheduling. Pass a stable delivery identity where supported. Keep one successful terminal record per event and sink.

## Alternatives rejected

Retrying the whole event repeats successful deliveries. A long lease alone leaves stale worker updates and lost acknowledgments unresolved.

## Risks

Migration cannot infer which sinks received a partially delivered legacy event. Coordinate deployment to avoid old and new workers racing. A sink without deduplication can still receive a duplicate after successful delivery followed by a lost acknowledgment. A sink that internally delivers to several destinations, such as the webhook sink, still needs downstream deduplication within that fan-out.

## Verification

Use PostgreSQL fixtures for rollback on enqueue failure, successful enqueue with commit, expired-lease reclaim, stale result rejection, and independent retry when another sink succeeds. Verify migration with pre-existing pending and terminal rows. Verify sink idempotency using a supported test fixture; document the delivery guarantee for sinks that lack it. Run the embedded migrations in the events integration harness so it exercises the new schema.
