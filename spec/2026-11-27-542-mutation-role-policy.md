---
status: approved
issue: 542
intent: intent/2026-11-27-542-mutation-role-policy.md
---

# Spec: Enforce the current documented role contract

## Design

Require Admin for configuration, flow and policy writes covered by the documented contract. Admin and Writer may record evidence. Use explicit route gates and the existing principal. Assistant reads retain their current permissions, while persistent flow changes require Admin inside the handler. Preserve the dedicated authentication and approval capability checks.

The approved defaults extend Admin to control exceptions, service ownership, logical environment membership and configuration, environment registration and tags, allowlists, remediation decisions, attestation types, control links, and generic ServiceNow MCP tool calls. New environment registrations can change existing environment state. Scoped evidence and routine operations allow Writer or Admin, including training records, snapshot reevaluation, remediation proposals, ServiceNow change-gate and incident actions, and environment MCP verification.

Trail approval accepts Writer or Admin or a service principal with an explicit delegation capability when the existing delegation checks honor the request. Preserve the capability toggle and target identity validation.

## Alternatives rejected

A global write-role check would affect signed callbacks, login and read-only POST previews.

## Risks

Pipelines using Viewer or Auditor for evidence writes need the documented Writer role. Integrations that change configuration require Admin.

## Verification

Run local route authorization tests with each relevant credential and compare denied requests against unchanged tenant data.
