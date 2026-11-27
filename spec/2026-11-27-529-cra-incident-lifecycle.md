---
status: draft
issue: 529
intent: intent/2026-11-27-529-cra-incident-lifecycle.md
---

# Spec: Track CRA deadlines and evidence of submission

## Design

Keep the existing window report in `pkg/api/cra_incidents.go` and add a tenant-scoped case lifecycle for both supported case types. Store explicit awareness, available corrective or mitigating measure, stage exports and actual submission timestamps with a payload digest and operator identity. Calculate early warning and notification 24 and 72 hours from awareness. Calculate the vulnerability final deadline 14 days from measure availability and the severe-incident final deadline one calendar month from notification submission, with regulation exceptions and continuing-incident reporting handled in the confirmed requirements. Reuse the VEX/impact index to link artifacts and the #519 outbox for deduplicated due and overdue events. Generate versioned structured exports with a mapping verified against ENISA's supported workflows. Treat export as a draft and attest a confirmed submission on each affected trail exactly once. Deduplicate reminders by case, stage and deadline revision. Preserve past deadlines and events when an authorized correction changes a current deadline.

## Alternatives rejected

Treating scanner discovery as operator awareness can set the wrong clock. Treating an export as a submission can falsely mark a deadline complete.

## Risks

Confirm stage fields, any exceptions, and export compatibility before promising acceptance by the reporting platform. Record deadline changes and protect sensitive case data from unauthorized tenants and downstream notification channels. [Article 14](https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng) [ENISA Single Reporting Platform](https://www.enisa.europa.eu/topics/product-security/vulnerability-services/eu-incident-response-and-cyber-crisis-management/single-reporting-platform-srp)

## Verification

Use an injected clock to test stage triggers, month boundaries, unknown measure availability, and overdue deduplication. Verify tenant and role checks, immutable submitted-payload identity, export without transition, and idempotent submission attestations.
