---
status: approved
issue: 526
spec: spec/2026-11-27-526-recording-replay.md
---

# Plan: Queue evidence during recording outages

## Approved design

Add opt-in fail-open handling to the trail creation, artifact report and attestation recording entry points in `cmd/cli/main.go` and their specialized recording paths. Use a durable, permission-restricted spool with 0700 directories and 0600 entries that atomically saves the request and attachment bytes before returning success, emits a warning, and binds each entry to an endpoint and tenant credential identity without persisting tokens. Store stable request IDs and dependency links. Support an offline trail reference for chained CLI work and resolve it to the resulting server ID on replay. Replay oldest ready entries first, use current credentials for the bound endpoint, retain entries until confirmed, and use server-side tenant-scoped idempotency for ambiguous transport or selected retryable server errors, rejecting conflicting reuse. Keep gating fail-closed by default. Keep gate overrides out of this release. A future explicit override requires its own durable evidence design.

### Alternatives rejected

Returning success on failure without durable spooling drops compliance evidence. A client-only retry cannot resolve an ambiguous successful write.

## Steps

Line references are from the reviewed base. Refresh them after dependent changes land.

1. **cmd/cli/main.go:223–452, 877–986 and specialized recording in cmd/cli/integrations.go, sbom.go, model.go and verify_image.go** — Inventory exact eligible commands. Add explicit opt-in spooling only to trail creation, artifact reporting and direct attestation records. Materialize exact payload and applicable attachments, then persist by atomic replacement and synchronize the entry and directory metadata, using 0700 directories and 0600 entries before warning and emitting success. Bind stable request IDs and dependencies to the destination and non-secret tenant credential identity. Keep authentication out of the spool. Report spool write failures, final HTTP errors and gate failures normally.
2. **pkg/api/server.go:659–790, pkg/api/ingest_handlers.go:96–270 and pkg/db/migrations/** — Add tenant-scoped idempotency for supported writes with unique operation ID, content fingerprint and conflict rejection. Persist a response with the write outcome so an ambiguous successful response replays without duplicate evidence. Coordinate with #519 and #521. Account for attachment completion before acknowledging the result.
3. **cmd/cli/main.go:35–162 and new cmd/cli/replay.go** — Replay oldest ready requests with current credentials for the bound destination and durable mappings from offline trail references to server IDs. Coordinate concurrent replay and delete only confirmed entries. Keep dependent entries until prerequisites succeed. Document eligible transport/5xx conditions and queue protection, retention and ephemeral runner mounts. Keep gate overrides outside this release.

### Implementation decisions

1. Carry a UUID in `Idempotency-Key`. Authenticate the writer and verify ownership before replaying a stored result. Use a tenant-scoped advisory transaction lock, an evidence fingerprint, and migration `0030_recording_operations.sql` to commit the response with the evidence. Complete attachment uploads and metadata writes before recording success, using stable object keys for keyed retries.
2. Bind queue entries to a digest of the configured endpoint and credential. An opaque credential gives the CLI no offline tenant identity. Replay therefore requires the same credential. Use `FIDES_SPOOL_DIR` for persistent runners. Trail mappings retain their server UUID without retaining the request body after confirmation.
3. Queue selected temporary transport failures and HTTP 502, 503 and 504 responses. Treat authentication, TLS identity, redirect, and validation failures as terminal. Preserve the idempotency table across rollbacks and run the updated server before enabling fail-open on its clients.

## Risks

CI runners with ephemeral disks can lose spooled evidence. The spool can contain sensitive evidence and can fill up. Document retention, artifact mounting and the exact commands and statuses eligible for spooling.

## Tests

Run `go test ./cmd/cli ./pkg/api ./pkg/db` with PostgreSQL coverage. Test permission failures, interrupted writes and post-commit lost acknowledgments, conflicting ID reuse, concurrent replay, wrong target/tenant, attachment bytes, dependent ordering and fail-closed gating.

For code changes, run `go build ./...`, `go vet ./...`, `go test ./...` and `gosec -severity medium -confidence high ./...`. With the repository CI PostgreSQL 15 fixture and `FIDES_TEST_DB_DSN` set, run `go test -p 1 ./pkg/db/ ./pkg/api/ ./pkg/events/ ./pkg/servicenow/ -run "Integration|EndToEnd" -v`. Confirm relevant cases ran and record the result.

Exercise network failure, retryable 5xx, final 4xx, permission and disk failures, attachments, dependent records, and interruption after server commit. Verify replay deduplicates and concurrent replays cannot delete unconfirmed entries. Check that an unavailable server still fails a default gate.

## Rollback

Disable fail-open if needed while retaining queued records and idempotency data. Drain or preserve the queue before downgrading. Avoid replaying ambiguous writes on a binary that lacks server deduplication.
