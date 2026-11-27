---
status: approved
issue: 557
intent: intent/2026-11-27-557-signer-proof-retention.md
---

# Spec: Retain verifiable signer proof material

Keep the original Sigstore bundle or DSSE proof and the artifact binding inputs for new provenance records. For registry-discovered signatures, keep the exact signed statement bytes. Reuse explicit local auditor trust and identities for offline verification and leave the existing online verifier behavior intact.

Use real local fixtures and independently trusted inputs for verification.
