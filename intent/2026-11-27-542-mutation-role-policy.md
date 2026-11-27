---
status: approved
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

The owner approved Admin for governance and Writer or Admin for evidence and routine operations. Explicit approval delegation remains available under its existing capability rules.
