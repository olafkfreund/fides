---
status: draft
issue: 556
spec: spec/2026-11-27-556-evidence-commitments.md
---

# Plan: Commit evidence inputs to the attestation chain

New entries use a domain-separated versioned commitment over the legacy entry inputs and canonical evidence inputs. Store artifact linkage, signature metadata, actual attachment identities, sizes and digests, and the policy definition read and applied during evaluation when applicable. Read these inputs within the existing append transaction. Keep legacy chain hashes and expose verification coverage separately.

Ledger and verification logic goes to Sol. A second Sol worker owns API, schema, and integration. Agy reviews the plan and diff.

## Steps

1. In pkg/ledger/ledger.go, add an explicit versioned hash and verify mixed
   chains. Keep ContentHash unchanged for historical verification. Use
   Entry.Version and Entry.Evidence for the numeric version and canonical
   commitment JSON. Version 0 or 1 retains legacy semantics. Version 2 binds
   the evidence JSON. Report legacy and unhashed coverage explicitly.
2. In pkg/api/attestation_chain.go, pkg/api/ingest_handlers.go, the attestation
   policy evaluation path, and migration 0034, compute and store version 2
   evidence inputs with new attestations. Commit attachment digests before
   shared append, then compare recorded inputs to stored attestation and
   attachment metadata during verification. Preserve legacy proofs and
   make missing historical inputs distinguishable from invalid new records.
3. Test the real ingestion transaction, byte-derived attachment hashes,
   policy edits after recording, mixed chains, and historical anchors.

## Verification

Run Go build, vet, race tests, lint, security scanners, and PostgreSQL 15
integration against the completed revision. Confirm historical evidence still
verifies under its original rules.

## Rollback

Preserve observed evidence, stored hashes, and proof bytes. Use a compatible
reader before enabling a write format older binaries cannot verify.
