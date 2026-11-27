---
status: draft
issue: 540
author: olafkfreund
---

# Intent: Keep concurrent attestation chains valid

## Problem

The #523 regression accepted 16 concurrent attestation uploads to one trail. Its public verifier returned an invalid chain at link 2.

## Proposed outcome

Successful appends to one trail always have distinct, consistently ordered links. The verifier reports an intact chain after concurrent uploads.

## Affected users and systems

PostgreSQL-backed Fides attestation writers, trail verification, audit exports, and optional event delivery.

## Constraints

Retain existing stored evidence and hashes, tenant scoping, and outbox atomicity.

## Open questions

None.
