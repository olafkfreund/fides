---
status: approved
issue: 523
intent: intent/2026-11-27-523-critical-regressions.md
---

# Spec: Cover critical request and concurrency paths

## Design

Build on `pkg/api/*_integration_test.go`, `pkg/db/*_integration_test.go`, `pkg/events/events_integration_test.go` and `.github/workflows/go-build.yml`. Check actual mutating API routes over tenant role and credential combinations using isolated fixtures. Exercise concurrent appends to a single trail and verify the resulting chain. Assert outbound policy consistently rejects disallowed redirects and address classes with injected test DNS and transports. Add dispatcher lease tests with #519 and stdio MCP contract tests with #517, keeping each test at the layer that owns the behavior. Keep assertions tied to the intended behavior if they uncover a production defect and link the corrective issue before marking coverage complete.

## Alternatives rejected

A single giant PostgreSQL test would mix independent failure modes and require a database for client transport and codec checks.

## Risks

An authorization fixture that exits at input validation before reaching the authorization distinction can falsely pass. Concurrency tests need deterministic barriers or timestamps and isolated data. Use host-local fixtures only.

## Verification

Run the named suites under the existing CI unit and PostgreSQL jobs. Verify allowed and denied route cases, tenant separation, final chain validity, outbound policy, competing worker ownership, and MCP success and HTTP-error handling.
