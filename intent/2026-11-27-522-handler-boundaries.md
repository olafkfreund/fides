---
status: draft
issue: 522
author: olafkfreund
---

# Intent: Give API and CLI code clear domain boundaries

## Problem

Large mixed-purpose source files make changes hard to review. Environment list and audit export duplicate drift enrichment, and AI policy fallback can produce invalid JSON for ordinary input containing quotes or line breaks.

## Proposed outcome

API and CLI code is grouped by domain, environment drift enrichment has one shared path, and policy fallback emits valid JSON. Existing behavior has regression coverage and large source files are brought within the agreed size target.

## Affected users and systems

pkg/api, cmd/cli, and their API and CLI callers.

## Constraints

Sequence the structural moves after correctness changes in overlapping paths. Keep route contracts and CLI outputs compatible, with the JSON correctness fix called out explicitly.

## Open questions

Confirm whether the size target covers CLI main and whether Swagger generation belongs in this issue.
