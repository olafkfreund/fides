---
status: draft
issue: 525
intent: intent/2026-11-27-525-cloud-snapshots.md
---

# Spec: Record snapshots from Cloud Run, Azure and S3

## Design

Add positional runtime names `cloud-run`, `azure-apps`, and `s3` to `cmd/cli/main.go` using the injectable provider collection pattern in `cmd/cli/aws_snapshot.go`. Bound provider calls with a context. Cloud Run captures actual serving revisions and their provider-reported resolved image digests. Azure captures resolved digests for containers or hashes verifiable deployment package bytes for code-based App Service and Functions. For S3, include all pages and hash a canonical, key-ordered manifest of verified object content digests, reading exact version IDs or using conditional requests for unversioned objects under the configured prefix. Prefer immutable provider versions and fail when observation is partial or a digest cannot be verified. Reuse the existing snapshot payload and add environment types to the API, portal and a Terraform environment resource using the environment API.

## Alternatives rejected

Mutable image tags, Azure deployment IDs and S3 ETags alone are insufficient content evidence. A new snapshot API would duplicate ingestion and drift logic.

## Risks

Provider feature coverage and access differ by deployment type. Checking actual S3 bytes can incur significant reads, and mutable prefixes do not provide an atomic view. Document supported setups, read costs, concurrency limits, and partial observation behavior.

## Verification

Use recorded fixtures for multiple serving revisions, container and package deployments, multi-page S3 prefixes, reordered provider results, and provider errors. Verify no snapshot is sent on incomplete observation and existing runtimes still work. Verify CLI docs and Terraform type handling.
