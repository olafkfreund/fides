---
status: draft
issue: 521
author: olafkfreund
---

# Intent: Keep each RLS request on one database connection

## Problem

RLS middleware pins a pooled connection, while some handlers begin work on another. Requests can exhaust the pool waiting for that second connection. Other paths query with a cursor still open, and scope cleanup ignores reset failure.

## Proposed outcome

Scoped requests and transactions use their assigned connection. Queries complete without an active cursor blocking follow-up work. A failed tenant reset discards that connection. A restricted-role PostgreSQL test exercises concurrent scoped requests above pool capacity and tenant isolation.

## Affected users and systems

RLS request middleware, database scoping, snapshot and settings APIs, framework catalog imports, and artifact reads.

## Constraints

Preserve tenant scoping and transaction boundaries. Coordinate with #519, #520 and #522.

## Open questions

None.
