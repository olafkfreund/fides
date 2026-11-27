---
status: draft
issue: 528
author: olafkfreund
---

# Intent: Verify signed audit packs offline

## Problem

Existing audit exports provide a server-computed verdict and lack the full proof and evidence needed by an offline auditor. Some export reads may also omit data after a database error.

## Proposed outcome

The export includes signed evidence and the materials needed to verify file digests, chain integrity, approvals, signer proofs and available timestamps offline. Export fails visibly if required inputs cannot be read. A CLI command and auditor guide cover trusted inputs and tests reject altered packs.

## Affected users and systems

Trail audit export, attachments, ledger, signing and timestamp proofs, CLI and external auditors.

## Constraints

Depends on the separately tracked integrity prerequisites. Anchor verification in auditor-trusted keys and roots, and distinguish missing historical proofs from verified evidence.

## Open questions

Identify the prerequisite issues and agree on the trust, key rotation, and legacy-evidence policy. Does tamper detection also cover ZIP container metadata?
