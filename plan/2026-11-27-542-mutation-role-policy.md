---
status: draft
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

1. **`pkg/api/server.go:68`, `pkg/api/auth_middleware.go:158`** — Add explicit Admin-only and Writer-or-Admin gates to documented API mutations identified by the #523 inventory. Apply the gate before body validation or side effects. Preserve existing route registration, authentication and public callback behavior. Exercise the #523 authorization cases.
2. **`pkg/api/assistant_handlers.go:191`** — Require Admin on each branch that persists a flow, including the model and no-model paths. Check that read-only chat is available at the current roles. Keep existing tenant scoping and assistant behavior.
3. **`docs/first-run.md:57`, `web/first-run.md:57`** — State the enforced rules and existing capability exception together. Run the checks below and link #523.

## Tests

Run the #523 route matrix with local PostgreSQL 15 and verify denied requests cause no writes. Run the Go build, vet, race suite, lint, gosec and standard integration selection with Go 1.26.11.

## Rollback

Revert the role gates through a PR and retain tenant and authentication checks.
