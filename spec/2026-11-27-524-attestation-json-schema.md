---
status: draft
issue: 524
intent: intent/2026-11-27-524-attestation-json-schema.md
---

# Spec: Validate custom attestation payloads against JSON Schema

## Design

Reuse the nullable JSONB schema in `schema.sql` and the current string-valued API schema field in `pkg/api/ingest_handlers.go`. Normalize absent schema to SQL NULL. Support Draft 2020-12 with local references and bounded compilation and validation. Reject invalid new definitions on write. Existing invalid definitions fail affected attestations closed with a stable configuration reason and can be corrected through tenant-scoped type management. Load schema with jq rules during ingestion and persist bounded, structured validation reasons on the attestation without mutating the submitted payload. A valid payload must still pass jq. Expose schema through CLI file input, tenant-scoped type create/read/list/update/delete API, portal and the Terraform provider under `terraform-provider-fides/internal/provider`.

## Alternatives rejected

A second schema column would duplicate the current source of truth. Remote reference retrieval introduces network and reproducibility dependencies. Encoding reasons into the submitted payload would change evidence bytes.

## Risks

There may be existing invalid schema values because writes were not compiled. Document remediation and keep empty types compatible. Terraform adoption needs a clear import and update contract. Historical evidence retains its recorded verdict and input.

## Verification

Test create/read/update with and without schema, invalid definitions, tenant isolation, invalid payload persistence, success with valid payload, and jq interaction. Add CLI and Terraform resource lifecycle checks, and run the portal build.
