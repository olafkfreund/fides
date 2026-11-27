---
status: approved
issue: 528
spec: spec/2026-11-27-528-offline-audit-pack.md
---

# Plan: Verify signed audit packs offline

## Approved design

Wait for real attachment digests and ledger proof coverage. Build a versioned export on `pkg/api/audit.go` with a manifest containing exact member names and sizes, SHA-256 digests, trail chain head and coverage, policy versions, and references to evidence, approvals, attestations, signer bundles and RFC 3161 tokens. Propagate query, iteration and archive-write errors before delivering an export. Use a consistent export snapshot. Sign the SHA-256 digest of the exact completed archive bytes with a domain-separated detached signature carrying the signer key ID, so ZIP metadata is covered. Deliver the signature alongside the export. `fides verify-pack pack.zip` reads its sibling signature and explicitly configured trusted keys and roots. Verify container signature, membership, digests, chain and included proofs offline and report known missing historical proof separately. Verify all proofs in the pack before reporting success, and use a distinct incomplete result when required historical proof is missing.

### Alternatives rejected

A signed manifest alone leaves ZIP container bytes outside its signature. Using trust roots clipped into the same untrusted archive as the proof would let the archive choose its own trust anchor.

## Steps

Line references are from the reviewed base. Refresh them after dependent changes land.

1. **pkg/api/audit.go:21–151, pkg/api/ingest_handlers.go:297–318, pkg/api/attestation_chain.go:17 and pkg/api/anchor.go:66–130** — Confirm the attachment hash/retention and ledger coverage prerequisites before implementation. Read a consistent tenant export snapshot and close the result sets safely. Collect all required evidence, exact members, chain data, policies, approvals, attachment bytes and signer/timestamp proof material. Propagate reads, scans, iterations and archive errors and only offer a complete staged export. Preserve existing legacy routes for clients that use them.
2. **pkg/api/audit.go:85–124, pkg/crypto and pkg/vault** — Build the versioned manifest and bounded ZIP. Sign the SHA-256 digest of its exact bytes with a domain-separated detached signature including key ID. Source key material securely at runtime. Deliver the signature with the archive, documenting how it is saved as a sibling and how independently trusted keys are distributed and rotated.
3. **cmd/cli/main.go:35–162, pkg/ledger/ledger.go:67, pkg/tsa/tsa.go:29 and pkg/cosignverify/sigstore.go:37** — Add `verify-pack` with no server dependency. Require explicit auditor trust, verify the exact archive and membership before traversing bounded entries, then validate digests, chain and all stored proof classes. Reject duplicate/unlisted/missing members and distinguish incomplete required historical proof from invalid evidence. Describe exit status and trust inputs in the auditor guide.

## Prerequisite check

The two Sol reviewers checked main at `2417d0c`. #526 records real
attachment sizes and SHA-256 digests for new uploads. #540 serializes ledger
appends, and trail anchors retain raw RFC 3161 timestamp tokens.

The offline pack still depends on a versioned ledger commitment for
attachment and signer inputs, retention of original signer proofs, and
historical policy version capture. Older attachment records can lack the
original digest. Retain their historical status even if the current object can
be read. The approved export must verify stored size and digest on read.
Preserve existing ledger hashes and anchors through prerequisite updates.

The public issue names separate integrity work and gives no dependency IDs.
Keep validation claims limited to the recorded evidence until those updates
land. This check leaves the export and verifier implementation pending.

## Risks

Identify the ledger and attachment prerequisites before implementation. Key rotation and verification of historical packs require retained trusted key IDs. Enforce archive bounds, reject duplicate or unlisted members, and document required proof classes and legacy limitations.

## Tests

Run `go test ./cmd/cli ./pkg/api ./pkg/ledger ./pkg/tsa ./pkg/cosignverify` including offline fixtures and PostgreSQL export tests. Verify byte-level and member-level tampering, altered proofs, read failures, rotation, independently trusted roots and incomplete legacy evidence.

For code changes, run `go build ./...`, `go vet ./...`, `go test ./...` and `gosec -severity medium -confidence high ./...`. With the repository CI PostgreSQL 15 fixture and `FIDES_TEST_DB_DSN` set, run `go test -p 1 ./pkg/db/ ./pkg/api/ ./pkg/events/ ./pkg/servicenow/ -run "Integration|EndToEnd" -v`. Confirm relevant cases ran and record the result.

Verify a good pack in an offline test with local roots and fail on changed archive bytes or proofs, missing or duplicate members, untrusted signatures, and injected query or stream failures. Publish an auditor guide covering trust setup and verification output.

## Rollback

Disable issuance of the new format if needed. Preserve issued archives, detached signatures, verification tools and historical public trust material. Restore the existing export path without changing retained evidence.
