---
status: draft
issue: 518
author: olafkfreund
---

# Intent: Bound jq evaluation and require every result to pass

## Problem

The shared jq policy evaluator waits without a time budget and returns on the first boolean. Rules that produce multiple results can pass despite a later failure, and long evaluation can hold up compliance requests.

## Proposed outcome

Evaluation respects a bounded deadline. A rule passes only when it produces at least one result and all results are boolean true. Tests cover success, a later false result, empty and non-boolean output, errors, and cancellation.

## Affected users and systems

The shared policy engine and its attestation, environment, flags and ServiceNow callers.

## Constraints

Keep the decision consistent across callers. Preserve existing evidence and error-reporting contracts where compatible with fail-closed evaluation.

## Open questions

Choose a deadline and decide how the overall attestation budget applies across multiple rules.
