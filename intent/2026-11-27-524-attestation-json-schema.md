---
status: draft
issue: 524
author: olafkfreund
---

# Intent: Validate custom attestation payloads against JSON Schema

## Problem

Custom attestation types already have an optional schema field alongside jq rules, but ingestion only evaluates the jq rules. A schema currently cannot determine whether a payload passes.

## Proposed outcome

Operators can add or update an optional schema through the API, CLI and Terraform and inspect it in the portal. If a payload violates the schema, Fides stores the attestation as non-compliant with validation reasons. Tests cover accepted and rejected payloads and types without a schema.

## Affected users and systems

Attestation type management, ingestion, portal, Terraform and documentation.

## Constraints

Reuse the existing schema representation where compatible. Preserve behavior for types without a schema and decide how to handle legacy values. Keep schema evaluation local and bounded. The Terraform provider currently has no attestation type resource.

## Open questions

Choose the supported JSON Schema dialect, reference policy and error format.
