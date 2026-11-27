---
status: approved
issue: 556
intent: intent/2026-11-27-556-evidence-commitments.md
---

# Spec: Commit evidence inputs to the attestation chain

New entries use a domain-separated versioned commitment over the legacy entry inputs and canonical evidence inputs. Store artifact linkage, signature metadata, actual attachment identities, sizes and digests, and the policy definition read and applied during evaluation when applicable. Read these inputs within the existing append transaction. Keep legacy chain hashes and expose verification coverage separately.

Use real local fixtures and independently trusted inputs for verification.
