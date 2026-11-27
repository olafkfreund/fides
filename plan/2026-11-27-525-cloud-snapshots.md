---
status: approved
issue: 525
spec: spec/2026-11-27-525-cloud-snapshots.md
---

# Plan: Record snapshots from Cloud Run, Azure and S3

## Approved design

Add positional runtime names `cloud-run`, `azure-apps`, and `s3` to `cmd/cli/main.go` using the injectable provider collection pattern in `cmd/cli/aws_snapshot.go`. Bound provider calls with a context. Cloud Run captures actual serving revisions and their provider-reported resolved image digests. Azure captures resolved digests for containers or hashes verifiable deployment package bytes for code-based App Service and Functions. For S3, include all pages and hash a canonical, key-ordered manifest of verified object content digests, reading exact version IDs or using conditional requests for unversioned objects under the configured prefix. Prefer immutable provider versions and fail when observation is partial or a digest cannot be verified. Reuse the existing snapshot payload and add environment types to the API, portal and a Terraform environment resource using the environment API.

### Alternatives rejected

Mutable image tags, Azure deployment IDs and S3 ETags alone are insufficient content evidence. A new snapshot API would duplicate ingestion and drift logic.

## Steps

Line references are from the reviewed base. Refresh them after dependent changes land.

1. **cmd/cli/main.go:520–710 and cmd/cli/aws_snapshot.go:30–156** — Add positional `cloud-run`, `azure-apps` and `s3` collectors using injected clients and bounded context. Capture recorded provider responses before finalizing field mappings. Collect all serving Cloud Run revisions and resolved digests. For Azure containers require a resolved digest, or obtain verified deployment package bytes and hash those for code-based App Service and Functions. For S3 fetch all listing pages, resolve exact object versions or use conditional requests, then hash a canonical key-ordered manifest of actual content digests. Fetch failures or unsupported configurations stop submission. Never treat a mutable tag, deployment ID or ETag as a content digest.
2. **pkg/api/environment_handlers.go:30–94, pkg/api/ingest_handlers.go:421, portal/src/app/(portal)/environments/page.tsx and terraform-provider-fides/internal/provider/provider.go:66** — Add accepted environment types and a Terraform resource using the environment API. Match existing environment lifecycle and archival behavior. Read by tenant and ID, preserve identity during updates and use the existing archive flow for resource removal. Add a tenant-scoped update route if the name-based upsert cannot update safely. Continue using the same snapshot ingress. Extend CLI help and maintained docs with supported deployment layouts, permissions, concurrency and read costs, and the non-atomic nature of mutable S3 prefixes.

### Implementation decisions

1. Cloud Run uses v1 service traffic status, including revisions with a zero-percent tagged URL. Each serving container is named `service/revision[/container]` and uses the platform's resolved digest. Reread the serving revision set before submitting.
2. Azure reads a running site's single, digest-pinned Linux container configuration or hashes the package bytes from Kudu or a versioned Azure Blob URL. Kudu uses Microsoft Entra auth at the site's HTTPS SCM origin. Blob requests use the configured public or signed URL on Azure Blob Storage. Reread the active package or runtime configuration before submitting.
3. S3 resolves the current version through `HeadObject` and compares its metadata to the list response. Use the existing AWS SDK v2 to stream exact versions or send an ETag precondition for unversioned objects. The AWS CLI streaming command requires direct key arguments, which would be interpreted as file parameters for some valid keys. S3 snapshot requests use their configured endpoint and reject redirects. Hash the JSON array of exact keys and their lowercase content digests in key order. An empty result hashes the empty JSON array. Reread the object set and metadata before submitting. Hash scope labels longer than the snapshot API's storage field.
4. Add tenant-scoped `GET` and Admin-only `PATCH` by environment UUID. Terraform uses create-only registration to avoid taking over an existing environment. Updating preserves the UUID and archive status, and destroy calls the archive endpoint.

## Risks

Provider feature coverage and access differ by deployment type. Checking actual S3 bytes can incur significant reads, and mutable prefixes do not provide an atomic view. Document supported setups, read costs, concurrency limits, and partial observation behavior.

## Tests

Use recorded provider fixtures for split traffic, multiple revisions, Azure container and verified package evidence, S3 pagination and result ordering, read errors and unverified digests. Confirm failed or partial reads never issue a snapshot. Run CLI/API tests, nested provider tests and portal build, and verify existing runtimes still submit.

For code changes, run `go build ./...`, `go vet ./...`, `go test ./...` and `gosec -severity medium -confidence high ./...`. With the repository CI PostgreSQL 15 fixture and `FIDES_TEST_DB_DSN` set, run `go test -p 1 ./pkg/db/ ./pkg/api/ ./pkg/events/ ./pkg/servicenow/ -run "Integration|EndToEnd" -v`. Confirm relevant cases ran and record the result.

For portal changes, read `portal/AGENTS.md` and the relevant installed Next.js guide. Run `NODE_ENV=development npm ci --include=dev` in `portal/`, then unset `NODE_ENV` and run `npm run build`. Edit portal source files and keep the generated pages untouched.

Use recorded fixtures for multiple serving revisions, container and package deployments, multi-page S3 prefixes, reordered provider results, and provider errors. Verify no snapshot is sent on incomplete observation and existing runtimes still work. Verify CLI docs and Terraform type handling.

## Rollback

Revert the new collector paths and resource registration while preserving existing environment records and snapshot history. Document provider and Terraform state handling before downgrading an installed deployment.
