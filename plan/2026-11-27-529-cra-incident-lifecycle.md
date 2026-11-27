---
status: draft
issue: 529
spec: spec/2026-11-27-529-cra-incident-lifecycle.md
---

# Plan: Track CRA deadlines and evidence of submission

## Approved design

Keep the existing window report in `pkg/api/cra_incidents.go` and add a tenant-scoped case lifecycle for both supported case types. Store explicit awareness, available corrective or mitigating measure, stage exports and actual submission timestamps with a payload digest and operator identity. Calculate early warning and notification 24 and 72 hours from awareness. Calculate the vulnerability final deadline 14 days from measure availability and the severe-incident final deadline one calendar month from notification submission, with regulation exceptions and continuing-incident reporting handled in the confirmed requirements. Reuse the VEX/impact index to link artifacts and the #519 outbox for deduplicated due and overdue events. Generate versioned structured exports with a mapping verified against ENISA's supported workflows. Treat export as a draft and attest a confirmed submission on each affected trail exactly once. Deduplicate reminders by case, stage and deadline revision. Preserve past deadlines and events when an authorized correction changes a current deadline.

### Alternatives rejected

Treating scanner discovery as operator awareness can set the wrong clock. Treating an export as a submission can falsely mark a deadline complete.

## Steps

Line references are from the reviewed base. Refresh them after dependent changes land.

1. **pkg/api/cra_incidents.go:43–110, pkg/api/impact.go:101 and pkg/db/migrations/** — Keep discovery read-only and add tenant-scoped cases for both Article 14 categories. Store explicit awareness, affected artifact/trail links, milestone timestamps and immutable export/submission history with operator identity and digest. Calculate early warning and notification at 24 and 72 hours from awareness. Calculate vulnerability final reporting from 14 days after measure availability and severe-incident final reporting from one calendar month after notification. Confirm specified exceptions and ongoing-incident requirements against the source before coding those transitions. Use a pending deadline when its trigger is unknown and retain correction history.
2. **cmd/server/main.go:240–260 and pkg/events/events.go:52** — After #519, schedule due and overdue events with an injected clock and unique case/stage/deadline revision identity. Only authorized users may link evidence, correct dates or confirm submissions. Send minimal safe event content and preserve prior overdue records after deadline corrections.
3. **pkg/api/server.go:144, pkg/api/swagger.go:180, cmd/cli/integrations.go:531–554 and pkg/api/ingest_handlers.go:96–270** — Add case API and CLI, versioned structured manual exports, and idempotent attestation of actual confirmed submissions on affected tenant trails using the shared evidence path. Verify supported ENISA workflows before claiming format compatibility. Keep export and filing distinct.

## Risks

Confirm stage fields, any exceptions, and export compatibility before promising acceptance by the reporting platform. Record deadline changes and protect sensitive case data from unauthorized tenants and downstream notification channels. [Article 14](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng) [ENISA Single Reporting Platform](https://www.enisa.europa.eu/topics/product-security/vulnerability-services/eu-incident-response-and-cyber-crisis-management/single-reporting-platform-srp)

## Tests

Run API/CLI, PostgreSQL and event tests using an injected clock. Cover hours, calendar month boundaries, missing triggers, deadline corrections and reminder deduplication, tenant and role boundaries, correct payload digest and repeat submissions. Verify the existing window report.

For code changes, run `go build ./...`, `go vet ./...`, `go test ./...` and `gosec -severity medium -confidence high ./...`. With the repository CI PostgreSQL 15 fixture and `FIDES_TEST_DB_DSN` set, run `go test -p 1 ./pkg/db/ ./pkg/api/ ./pkg/events/ ./pkg/servicenow/ -run "Integration|EndToEnd" -v`. Confirm relevant cases ran and record the result.

Use an injected clock to test stage triggers, month boundaries, unknown measure availability, and overdue deduplication. Verify tenant and role checks, immutable submitted-payload identity, export without transition, and idempotent submission attestations.

## Rollback

Disable reminder scheduling and new writes if rollback requires it. Preserve case history, actual submissions, deadlines and associated evidence. Reconcile pending reminders without invalidating prior filing records.
