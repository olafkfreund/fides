---
status: draft
issue: 541
intent: intent/2026-11-27-541-outbound-destination-policy.md
---

# Spec: Guard outbound webhook and ServiceNow connections

## Design

Reuse one public HTTPS policy for webhook and ServiceNow. Validate the configured endpoint, the destination after DNS resolution at dial time, and each redirect. Allow same-origin HTTPS redirects and reject other redirect origins. Keep credentials, retry behavior, and timing as implemented. A direct guarded transport enforces the destination at the connection boundary.

## Alternatives rejected

A preflight URL check alone cannot enforce the policy at the point of connection. A global restriction would change integrations whose configured destinations can be internal.

## Risks

Configured cross-origin redirects and proxy-dependent paths need direct public HTTPS endpoints. Keep this change scoped to the two public endpoint clients.

## Verification

Check injected DNS classifications and synthetic allowed and denied redirects without real outbound destinations. Run webhook and ServiceNow tests, standard Go checks, and the PostgreSQL test selection.
