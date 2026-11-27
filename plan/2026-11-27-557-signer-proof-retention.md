---
status: approved
issue: 557
spec: spec/2026-11-27-557-signer-proof-retention.md
---

# Plan: Retain verifiable signer proof material

Keep the original Sigstore bundle or DSSE proof and the artifact binding inputs for new provenance records. For registry-discovered signatures, keep the exact signed statement bytes. Reuse explicit local auditor trust and identities for offline verification and leave the existing online verifier behavior intact.

Sigstore proof retention and offline verification go to Sol. A second Sol worker owns Git provider proof retention. Agy reviews the plan and diff.

## Steps

1. In pkg/cosignverify and cmd/cli/verify_image.go, retain the exact parsed
   bundle or original signed payload with new successful verification
   evidence. Add verification from the retained proof using independent
   local trust and an identity policy with no registry or TUF lookup.
2. In pkg/gitstatus/attestations.go and the attestation fetch handler, retain
   original proof bytes alongside the existing normalized statement and
   provider context. Preserve existing display and subject linkage behavior.
   Distinguish proof retention from independent verification.
3. Cover key-based and keyless trust wiring, digest mismatch, altered
   proofs, absent historical proof, and unauthenticated offline behavior
   with local test fixtures. Preserve the existing online commands.

## Verification

Run Go build, vet, race tests, lint, security scanners, and PostgreSQL 15
integration against the completed revision. Confirm historical evidence still
verifies under its original rules.

## Rollback

Preserve observed evidence, stored hashes, and proof bytes. Use a compatible
reader before enabling a write format older binaries cannot verify.
