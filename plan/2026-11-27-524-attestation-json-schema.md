---
status: approved
issue: 524
spec: spec/2026-11-27-524-attestation-json-schema.md
---

# Plan: Validate custom attestation payloads against JSON Schema

## Approved design

Reuse the nullable JSONB schema in `schema.sql` and the current string-valued API schema field in `pkg/api/ingest_handlers.go`. Normalize absent schema to SQL NULL. Support Draft 2020-12 with local references and bounded compilation and validation. Reject invalid new definitions on write. Existing invalid definitions fail affected attestations closed with a stable configuration reason and can be corrected through tenant-scoped type management. Load schema with jq rules during ingestion and persist bounded, structured validation reasons on the attestation without mutating the submitted payload. A valid payload must still pass jq. Expose schema through CLI file input, tenant-scoped type create/read/list/update/delete API, portal and the Terraform provider under `terraform-provider-fides/internal/provider`.

### Alternatives rejected

A second schema column would duplicate the current source of truth. Remote reference retrieval introduces network and reproducibility dependencies. Encoding reasons into the submitted payload would change evidence bytes.

## Steps

Line references are from the reviewed base. Refresh them after dependent changes land.

1. **schema.sql:105–115, pkg/api/ingest_handlers.go:32–70, 177–218 and pkg/models/models.go:48** — Reuse the nullable JSONB schema through the existing string-valued API field. Normalize absence to SQL NULL. Use an established validator that supports Draft 2020-12 with local-only references and size, depth, work and error-count bounds. Validate new definitions on create and update. Evaluate schema with jq in ingestion and inventory alternate type-based ingest paths. Persist stable structured reasons separately from the evidence payload, covering invalid legacy definitions without rewriting historical evidence.
2. **pkg/api/server.go:184 and pkg/db/migrations/** — Expose tenant-scoped type CRUD and list routes, document them in Swagger, and add a migration for persisted reasons. Bound list reads in accordance with the pagination contract. Keep `0001_init.sql` and `schema.sql` byte-identical by adding a migration and applying it in relevant test setup.
3. **cmd/cli/main.go:35–222, portal/src/app/(portal)/attestations/page.tsx and terraform-provider-fides/internal/provider/provider.go:66** — Add schema-file input and type management, inspect schemas and failure reasons in the portal, and register a Terraform resource with import, read, update and delete behavior. Use the established provider resource and client patterns. Document migration and correction of invalid definitions in maintained docs, with copies kept in sync.

### Implementation decisions

1. Use `github.com/santhosh-tekuri/jsonschema/v6` for Draft 2020-12. Its validator has no cancellation API, so the server performs compilation and validation in bounded child processes of the server executable. Each child has a deadline, with CPU and data-memory limits on Linux. The same evaluator covers direct reports, flag changes and ServiceNow checks that already evaluate tenant rules.
2. `PATCH` preserves an omitted schema and clears one set to JSON null or an empty string. Check the size of the PostgreSQL-normalized definition before storing a schema. Existing JSON Schema values remain subject to validation. Validation reasons use the new `0029_attestation_validation_errors.sql` migration and sit alongside the payload. Existing ledger hashes keep their current format.
3. Use the validator's default Go regular-expression engine. Document its syntax for `pattern` and `patternProperties`.

## Risks

There may be existing invalid schema values because writes were not compiled. Document remediation and keep empty types compatible. Terraform adoption needs a clear import and update contract. Historical evidence retains its recorded verdict and input.

## Tests

Run `go test ./pkg/api ./pkg/db ./cmd/cli` with PostgreSQL coverage, plus provider tests from `terraform-provider-fides` and the repo's portal build. Cover schema-less definitions, nullable updates, invalid new/legacy schemas, tenant separation, reasons persistence, unchanged payload, jq conjunction and resource lifecycle.

For code changes, run `go build ./...`, `go vet ./...`, `go test ./...` and `gosec -severity medium -confidence high ./...`. With the repository CI PostgreSQL 15 fixture and `FIDES_TEST_DB_DSN` set, run `go test -p 1 ./pkg/db/ ./pkg/api/ ./pkg/events/ ./pkg/servicenow/ -run "Integration|EndToEnd" -v`. Confirm relevant cases ran and record the result.

For portal changes, read `portal/AGENTS.md` and the relevant installed Next.js guide. Run `NODE_ENV=development npm ci --include=dev` in `portal/`, then unset `NODE_ENV` and run `npm run build`. Edit portal source files and keep the generated pages untouched.

Test create/read/update with and without schema, invalid definitions, tenant isolation, invalid payload persistence, success with valid payload, and jq interaction. Add CLI and Terraform resource lifecycle checks, and run the portal build.

## Rollback

Revert affected code across API and clients together. Retain schema and historical reason data. Treat deletion or reconstruction of enforcement state as a separate migration decision.
