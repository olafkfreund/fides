---
status: approved
issue: 542
spec: spec/2026-11-27-542-mutation-role-policy.md
coders:
  1: codex # Implement the shared role checks on route registrations.
  2: codex # Keep assistant reads usable and gate its flow writes.
reviewers:
  - agy # Compare the route policy and test evidence with the plan.
---

# Plan: Enforce the documented mutation roles

Use the existing request principal. Admin may configure flow, integration and policy settings. Writer and Admin may record evidence. Keep read and preview operations, tenant scoping, public callbacks and existing explicit approval capabilities.

## Steps

1. **`pkg/api/server.go:68`, `pkg/api/auth_middleware.go:158`** — Add explicit Admin-only and Writer-or-Admin gates to documented API mutations identified by the #523 inventory. Apply the gate before body validation or side effects. Under the owner's approved default, require Admin for control exceptions, service ownership, logical environment writes, environment registration and tags, allowlists, remediation decisions, attestation types, ServiceNow control links, and generic ServiceNow MCP tool calls. Allow Writer or Admin for training, snapshot reevaluation, remediation proposals, ServiceNow change-gate and incident operations, and environment MCP verification. In `pkg/api/approvals.go:102`, admit Writer or Admin, or a delegated service principal only when the existing capability and configuration checks honor the delegation. Preserve existing route registration, authentication and public callback behavior. Exercise the #523 authorization cases.
2. **`pkg/api/assistant_handlers.go:191`** — Require Admin on each branch that persists a flow, including the model and no-model paths. Check that read-only chat is available at the current roles. Keep existing tenant scoping and assistant behavior.
3. **`docs/first-run.md:57`, `web/first-run.md:57`** — State the enforced rules and existing capability exception together. Run the checks below and link #523.
4. **`pkg/api/approvals.go:102`, `artifact_handlers.go:25`, `servicenow_handlers.go:165`, and `servicenow_deployment_anchor.go:35`** — Use the existing tenant guard before writing against a requested trail or contacting ServiceNow. On artifact digest conflicts, update only a row belonging to the caller's organization. Check that a denied request leaves both tenants' rows unchanged.

## Tests

Run the #523 route matrix with local PostgreSQL 15 and verify denied requests cause no writes. Run the Go build, vet, race suite, lint, gosec and standard integration selection with Go 1.26.11.

## Rollback

Revert the role gates through a PR and retain tenant and authentication checks.
