---
status: approved
issue: 554
spec: spec/2026-11-27-554-reporter-dependencies.md
---

# Plan: Clear the reporter image scan

1. Update go.mod and go.sum to x/net v0.62.0 and gRPC v1.83.2. Review the solver
   changes and check that the release toolchain still supports the graph.
2. Run Go 1.26.11 build, vet, race tests, golangci-lint, gosec, and
   govulncheck. Run the existing PostgreSQL integration selection against a
   disposable PostgreSQL 15 fixture. Build a local reporter image and scan
   its archive with the existing Trivy severity and fixability filters.
   Preserve the published image workflow.
3. Confirm the reporter publish scan on main. If the update causes a
   regression, fix the compatibility issue while keeping patched versions.

The resolved graph and image checks apply to the root module. The Terraform
provider has a separate dependency graph and release workflow.

## Rollback

If the dependency change causes a confirmed compatibility regression, use a
revert PR or another patched version. Preserve existing image pins until the
replacement build passes the publish gate.
