---
status: approved
issue: 547
author: olafkfreund
---

# Intent: Keep Git attestation requests within their expected scope

## Problem

The outbound audit found that provider credentials need an explicit destination policy during attestation fetches.

## Proposed outcome

Attestation fetches work for the configured provider and for provider-issued signed public HTTPS download links. Git credentials remain scoped to the configured provider origin.

## Affected users and systems

GitHub and GitLab attestation fetches, including self-managed providers.

## Constraints

Preserve explicitly configured private API origins. Verify using synthetic local fixtures.

## Open questions

None.
