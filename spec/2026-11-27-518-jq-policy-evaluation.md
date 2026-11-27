---
status: approved
issue: 518
intent: intent/2026-11-27-518-jq-policy-evaluation.md
---

# Spec: Bound jq policy evaluation

## Design

Change `pkg/policy/policy.go` to accept a context and evaluate with the pinned gojq version's context-aware iterator. Pass the request context from the four production callers. Apply one proposed one-second evaluation budget to a standalone rule or to the complete attestation rule set. Preserve earlier request cancellation. A rule passes only if it emits at least one value and all values are boolean true. Return false for a false result and an error for empty output, a non-boolean or evaluator failure. Preserve failing-rule reasons and stop further evaluation once the shared context expires.

## Alternatives rejected

A timeout per rule would multiply the worst-case request duration. Returning after the first true result skips later outputs. The context-aware iterator already supplies cancellation without adding a worker pool.

## Risks

Existing rules that emit mixed values may now fail. The proposed one-second budget may need adjustment based on representative existing rules.

## Verification

Test true, multiple true outputs, a later false result, empty and mixed output, evaluator errors and a cancelled context with benign rules. Use a short test deadline to verify budget propagation without adding a slow test. Run the policy and affected API tests.
