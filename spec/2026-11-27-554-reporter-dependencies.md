---
status: approved
issue: 554
intent: intent/2026-11-27-554-reporter-dependencies.md
---

# Spec: Clear the reporter image scan

Resolve the root Go module to patched versions of x/net and gRPC. Use x/net
v0.62.0 and gRPC v1.83.2, and accept the transitive changes required by those
versions. Keep the current root Go language version and CI scan configuration.

Verify the module graph, build, race tests, PostgreSQL integration, and the
existing security scanners. Check the reporter Trivy outcome for the updated
binary.
