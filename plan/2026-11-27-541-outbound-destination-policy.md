---
status: draft
issue: 541
spec: spec/2026-11-27-541-outbound-destination-policy.md
coders:
  1: codex # Implement and verify the shared public HTTPS rules.
  2: codex # Wire the production clients and verify the existing request behavior.
reviewers:
  - agy # Review the policy boundaries and diff with local test evidence.
---

# Plan: Enforce the existing public HTTPS policy

Scope is the public webhook and ServiceNow clients. Preserve authorization, timeouts, retries, and same-origin HTTPS redirects. Use a direct guarded transport so the address policy applies to each actual dial.

## Steps

1. **`internal/outbound/`** — Add the smallest shared public HTTPS validator and HTTP client policy. Enforce the existing prohibited address classes with injectable DNS classification and a direct dial guard. Redirects must stay on the initial HTTPS origin and remain bounded. Verify using synthetic resolver and transport fixtures only.
2. **`pkg/webhooks/webhook.go:53`, `pkg/servicenow/client.go:63`** — Use the shared policy for both production clients, including their existing request validation seams. Preserve request headers, auth, timeout, retry rules, and response handling. Assert each constructor uses the guarded policy and run its existing tests.
3. **`docs/setup.md`, `web/setup.md`** — Document the two clients' direct public HTTPS endpoint and redirect contract in the paired setup guides. Keep other destinations and configuration as documented.

## Tests

Run focused Go tests for DNS and redirect policy and for both client packages. Run Go build, vet, race tests, golangci-lint, gosec, and PostgreSQL 15 integration using Go 1.26.11. Link #523 and #541 in the PR.

## Rollback

Revert the client wiring and the shared helper together through a PR. Use the existing request configuration during rollback.
