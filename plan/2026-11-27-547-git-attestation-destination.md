---
status: draft
issue: 547
spec: spec/2026-11-27-547-git-attestation-destination.md
coders:
  1: codex # Implement the origin decisions and guarded transport routing.
  2: codex # Exercise the policy with isolated synthetic clients.
reviewers:
  - agy # Verify provider credentials remain bounded and signed downloads still work.
---

# Plan: Scope Git attestation downloads

The configured provider origin can be private. Authenticated list and bundle requests stay on that origin. Cross-origin bundle URLs use the existing public HTTPS policy with a separate client and only noncredential headers.

## Steps

1. **`pkg/gitstatus/attestations.go:28,67,104,135` and `internal/outbound/https.go:73`** — Reuse the outbound origin normalization to compare scheme, DNS hostname, and effective port. Preserve the caller's client settings and restrict authenticated redirects to its initial origin. Send provider-issued cross-origin public HTTPS links through a fresh guarded client without provider headers, cookies, or proxy credentials. Preserve same-origin headers, bundle parsing, and timeouts.
2. **`pkg/gitstatus/attestations_test.go` and `internal/outbound/*test.go`** — Check same-origin requests, signed downloads with no provider credential, rejection of disallowed origins before delivery, and the configured private-provider fixture. Use a fake transport at the policy boundary. Preserve the existing API integration tests.
3. **`docs/features.md:335` and `web/features.md:335`** — Document the provider and signed download boundary and link #523.

## Tests

Run Go 1.26.11 build, vet, race tests, golangci-lint, gosec, and PostgreSQL integration. Use only synthetic local fixtures.

## Rollback

Revert through a PR. Existing provider configuration and stored attestations require no migration.
