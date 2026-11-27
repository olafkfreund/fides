---
status: draft
issue: 520
intent: intent/2026-11-27-520-bounded-list-pagination.md
---

# Spec: Bound API lists and environment enrichment

## Design

Inventory collection GET routes from `pkg/api/server.go` and their clients. Preserve JSON arrays and add a standard `Link: <…>; rel="next"` header. Apply a default page size of 100 and a maximum of 500. Use ordered keyset queries with a unique final tie-breaker, fetching one extra row. Validate cursor version and route, tenant and filter scope and always apply current authenticated tenant filters. Update maintained portal, CLI and MCP callers to follow same-origin next links, with response-size limits where the client needs only a subset. In `pkg/api/environment_handlers.go`, batch latest snapshots, running artifacts, allowlists and trail compliance for the selected environments with a constant query count. Batch artifact summary rows in `pkg/api/server.go` and surface query errors.

## Alternatives rejected

An envelope would break JSON decoding in array consumers. An offset can skip or repeat rows as the collection changes.

## Risks

External clients that ignore Link get the first page of newly bounded lists. Document that behavior and the release transition. Use stable sort order and retain explicit filters such as environment identity, because an opaque cursor is not authorization. The keyset provides ordering across pages, with ordinary visibility of collection changes between requests.

## Verification

Exercise empty/final pages, limit validation, duplicate sort keys, invalid or mismatched cursors, org boundaries, and all maintained consumers. Assert a constant query count as environment count grows and verify allowlist parity with ingest.
