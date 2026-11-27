---
status: approved
issue: 520
author: olafkfreund
---

# Intent: Bound API list responses and query work

## Problem

Many list handlers return every matching row. Environment enrichment issues queries for individual rows and can label allowlisted runtime images as shadow changes. Large responses and nested lookups increase request work.

## Proposed outcome

List routes enforce a maximum page size and expose a stable next cursor. Portal, CLI and MCP callers can enumerate all pages. Environment listing uses a bounded number of queries and its drift output respects the allowlist.

## Affected users and systems

API list routes, environment drift reporting, portal, CLI and MCP.

## Constraints

Preserve existing clients' response behavior through an explicit compatibility contract. Coordinate artifact query work with #521 and shared environment enrichment with #522.

## Open questions

Choose cursor transport and compatibility behavior for existing array responses.
