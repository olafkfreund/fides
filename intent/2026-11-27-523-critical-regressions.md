---
status: approved
issue: 523
author: olafkfreund
---

# Intent: Cover the critical request and concurrency paths

## Problem

Current tests leave gaps in authorization by route and role, concurrent evidence writes, outbound client policy, dispatch lease ownership and MCP request behavior.

## Proposed outcome

CI verifies mutating route authorization, chain integrity under concurrent appends, outbound redirect and address policy through local fixtures, concurrent dispatcher claims, and MCP request contracts.

## Affected users and systems

API authorization, chain storage, outbound integrations, event workers, MCP and PostgreSQL CI.

## Constraints

Use local defensive fixtures and reuse the existing integration harness. Coordinate delivery and MCP cases with #519 and #517.

## Open questions

Confirm which cases require PostgreSQL and which are faster and more reliable as host-local unit tests.
