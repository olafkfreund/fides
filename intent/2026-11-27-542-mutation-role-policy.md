---
status: draft
issue: 542
author: olafkfreund
---

# Intent: Enforce documented mutation permissions

## Problem

The #523 route inventory found a mismatch between the documented Admin and Writer permissions and route-level enforcement.

## Proposed outcome

Documented write operations require the corresponding role. The #523 matrix can verify the denial without changing tenant data.

## Affected users and systems

API sessions and service accounts, the portal assistant, and automation that posts evidence.

## Constraints

Preserve tenant checks, public signed callbacks, and existing delegated approval capabilities. Keep read-only operations available.

## Open questions

Operations without a documented minimum role require a separate policy decision.
