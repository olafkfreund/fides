---
status: draft
issue: 554
spec: spec/2026-11-27-554-reporter-dependencies.md
---

# Plan: Clear the reporter image scan

1. Update go.mod and go.sum to x/net v0.62.0 and gRPC v1.83.2. Review the solver
   changes and check that the release toolchain still supports the graph.
2. Run the root Go gates and the reporter image scan. Use a disposable
   PostgreSQL 15 fixture and preserve the current published image workflow.
3. Confirm the reporter publish scan on main. If the update causes a
   regression, fix the compatibility issue while keeping patched versions.

The resolved graph and image checks apply to the root module. The Terraform
provider has a separate dependency graph and release workflow.
