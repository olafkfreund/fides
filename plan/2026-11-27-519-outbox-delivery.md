---
status: approved
issue: 519
spec: spec/2026-11-27-519-outbox-delivery.md
---

# Plan: Make outbox delivery reliable across retries

## Approved design

Use the scoped transaction entry point from #521 so attestation and snapshot domain writes enqueue required events before commit whenever events are enabled. Inventory other producers and retain their current semantics in this issue. In `pkg/events` and a new migration, track state per event and stable configured sink identity. Freeze the fan-out set at first scheduling, initialize existing actionable events once, and preserve terminal history. Claim each delivery immediately before starting it with a lease token and check it on every result update. Budget attempts with a per-send context of 30 seconds under the existing 60-second default lease, scaling down the send timeout if a deployment uses a shorter lease and jitter retry scheduling. Pass a stable delivery identity where supported. Keep one successful terminal record per event and sink.

### Alternatives rejected

Retrying the whole event repeats successful deliveries. A long lease alone leaves stale worker updates and lost acknowledgments unresolved.

## Steps

Line references are from the reviewed base. Refresh them after dependent changes land.

1. **pkg/db/migrations/ and pkg/events/dispatcher.go:15–129** — After #521, add the next embedded migration for durable per-event sink deliveries, with a unique stable sink identity, state, attempt, retry time, and lease token. Initialize eligible legacy and new events once at first scheduling, freeze their configured sink identities, preserve terminal history, and leave unscheduled events pending if no sink is available. Update the integration harness to apply embedded migrations. Coordinate old dispatchers draining before activating the new delivery model.
2. **pkg/events/dispatcher.go:99–177, pkg/events/events.go:52 and pkg/webhooks/webhook.go:62** — Claim each due delivery immediately before sending. Use token-conditional state updates, a 30-second timeout against the default 60-second lease and a shorter timeout for a shorter lease, jittered existing bounded retries and a stable delivery identity where supported. Aggregate parent status without repeating a successful sink. Explain duplicate behavior after lost acknowledgments and within an internally fanned-out sink.
3. **pkg/api/ingest_handlers.go:219–270, 458–638** — When events are enabled, enqueue attestation and snapshot events inside the corresponding #521-backed transaction and return an error on enqueue failure. Preserve the events-disabled path. Preserve other enqueue producers and document this boundary. Keep external sink I/O out of the transaction.

## Risks

Migration cannot infer which sinks received a partially delivered legacy event. Coordinate deployment to avoid old and new workers racing. A sink without deduplication can still receive a duplicate after successful delivery followed by a lost acknowledgment. A sink that internally delivers to several destinations, such as the webhook sink, still needs downstream deduplication within that fan-out.

## Tests

Run PostgreSQL tests for commit and rollback, migrated pending and terminal records, no sinks, successful and failing sinks together, timed sends, forced lease reclaim and a stale worker acknowledgment. Exercise stable identity at an idempotent test sink. Run `go test ./pkg/events ./pkg/api ./pkg/db` with the integration DSN.

Keep the test packages serial when sharing the CI database.

For code changes, run `go build ./...`, `go vet ./...`, `go test ./...` and `gosec -severity medium -confidence high ./...`. With the repository CI PostgreSQL 15 fixture and `FIDES_TEST_DB_DSN` set, run `go test -p 1 ./pkg/db/ ./pkg/api/ ./pkg/events/ ./pkg/servicenow/ -run "Integration|EndToEnd" -v`. Confirm relevant cases ran and record the result.

Use PostgreSQL fixtures for rollback on enqueue failure, successful enqueue with commit, expired-lease reclaim, stale result rejection, and independent retry when another sink succeeds. Verify migration with pre-existing pending and terminal rows. Verify sink idempotency using a supported test fixture; document the delivery guarantee for sinks that lack it. Run the embedded migrations in the events integration harness so it exercises the new schema.

## Rollback

Drain workers before reverting. Keep delivery rows and reconcile or park pending deliveries before considering an old dispatcher, since it can resend terminal sink deliveries. Preserve payloads, attempts and successful history, and use a forward correction if incompatible workers have already run.
