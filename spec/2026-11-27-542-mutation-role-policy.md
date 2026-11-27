---
status: approved
issue: 542
intent: intent/2026-11-27-542-mutation-role-policy.md
---

# Spec: Enforce the current documented role contract

## Design

Require Admin for configuration, flow and policy writes covered by the documented contract. Admin and Writer may record evidence. Use explicit route gates and the existing principal. Assistant reads retain their current permissions, while persistent flow changes require Admin inside the handler. Preserve the dedicated authentication and approval capability checks.

## Alternatives rejected

A global write-role check would affect signed callbacks, login and read-only POST previews.

## Risks

Pipelines using Viewer or Auditor for evidence writes need the documented Writer role. Integrations that change configuration require Admin.

## Verification

Run local route authorization tests with each relevant credential and compare denied requests against unchanged tenant data.
