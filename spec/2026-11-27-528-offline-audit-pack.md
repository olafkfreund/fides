---
status: draft
issue: 528
intent: intent/2026-11-27-528-offline-audit-pack.md
---

# Spec: Verify signed audit packs offline

## Design

Wait for real attachment digests and ledger proof coverage. Build a versioned export on `pkg/api/audit.go` with a manifest containing exact member names and sizes, SHA-256 digests, trail chain head and coverage, policy versions, and references to evidence, approvals, attestations, signer bundles and RFC 3161 tokens. Propagate query, iteration and archive-write errors before delivering an export. Use a consistent export snapshot. Sign the SHA-256 digest of the exact completed archive bytes with a domain-separated detached signature carrying the signer key ID, so ZIP metadata is covered. Deliver the signature alongside the export. `fides verify-pack pack.zip` reads its sibling signature and explicitly configured trusted keys and roots. Verify container signature, membership, digests, chain and included proofs offline and report known missing historical proof separately. Verify all proofs in the pack before reporting success, and use a distinct incomplete result when required historical proof is missing.

## Alternatives rejected

A signed manifest alone leaves ZIP container bytes outside its signature. Using trust roots clipped into the same untrusted archive as the proof would let the archive choose its own trust anchor.

## Risks

Identify the ledger and attachment prerequisites before implementation. Key rotation and verification of historical packs require retained trusted key IDs. Enforce archive bounds, reject duplicate or unlisted members, and document required proof classes and legacy limitations.

## Verification

Verify a good pack in an offline test with local roots and fail on changed archive bytes or proofs, missing or duplicate members, untrusted signatures, and injected query or stream failures. Publish an auditor guide covering trust setup and verification output.
