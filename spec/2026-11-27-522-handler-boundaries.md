---
status: draft
issue: 522
intent: intent/2026-11-27-522-handler-boundaries.md
---

# Spec: Give API and CLI code clear domain boundaries

## Design

Move existing route handlers out of `pkg/api/server.go` into domain files for SSO, artifacts, compliance and the assistant. Split CLI integrations and the remaining large `cmd/cli/main.go` by existing subcommand families. Aim for roughly 800 lines per file by responsibility. Keep hand-maintained `pkg/api/swagger.go` as an explicit size exception in this issue. Share drift enrichment between environment list and audit export after #520 establishes query and allowlist semantics. Use JSON encoding for assistant policy fallbacks, including both the no-model and model-error paths.

## Alternatives rejected

Artificially splitting the handwritten spec or generating it during this refactor would add a separate documentation migration. Duplicating the drift helper preserves the existing risk of divergence.

## Risks

Mechanical moves can alter route wiring or CLI registration if declarations are lost. The drift refactor shares code with #520 and #521. Land targeted correctness work first and isolate JSON behavior changes from moves.

## Verification

Run repository Go checks and PostgreSQL integration. Verify route and CLI help parity, identical drift data where the two views overlap, and valid policy JSON for quotes and newlines.
