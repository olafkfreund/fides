---
status: approved
issue: 518
spec: spec/2026-11-27-518-jq-policy-evaluation.md
---

# Plan: Bound jq policy evaluation

## Approved design

Change `pkg/policy/policy.go` to accept a context and evaluate with the pinned gojq version's context-aware iterator. Pass the request context from the four production callers. Apply one proposed one-second evaluation budget to a standalone rule or to the complete attestation rule set. Preserve earlier request cancellation. A rule passes only if it emits at least one value and all values are boolean true. Return false for a false result and an error for empty output, a non-boolean or evaluator failure. Preserve failing-rule reasons and stop further evaluation once the shared context expires.

### Alternatives rejected

A timeout per rule would multiply the worst-case request duration. Returning after the first true result skips later outputs. The context-aware iterator already supplies cancellation without adding a worker pool.

## Steps

Line references are from the reviewed base. Refresh them after dependent changes land.

1. **pkg/policy/policy.go:18–70 and pkg/policy/policy_test.go:5–73** — Accept caller context and use the context-aware gojq iterator. Apply one one-second shared budget at entry, with earlier caller deadlines taking precedence. Require at least one boolean true and reject any non-true value. Preserve false versus evaluation error and keep failing-rule strings. Stop evaluating later rules on budget expiry. Keep an empty attestation rule list behaving as it does today.
2. **pkg/api/ingest_handlers.go:192, environment_handlers.go:598, flags.go:174 and servicenow_handlers.go:222** — Pass the relevant request context to the shared engine. Recheck all call sites. Test malformed rules, ordinary true/false and mixed outputs, empty outputs, cancellation, and a short deadline with benign fixtures.

## Risks

Existing rules that emit mixed values may now fail. The proposed one-second budget may need adjustment based on representative existing rules.

## Tests

Run `go test ./pkg/policy ./pkg/api` and `go test ./...`. Check representative stored rules for unexpected failures under the approved budget.

For code changes, run `go build ./...`, `go vet ./...`, `go test ./...` and `gosec -severity medium -confidence high ./...`. With the repository CI PostgreSQL 15 fixture and `FIDES_TEST_DB_DSN` set, run `go test -p 1 ./pkg/db/ ./pkg/api/ ./pkg/events/ ./pkg/servicenow/ -run "Integration|EndToEnd" -v`. Confirm relevant cases ran and record the result.

Test true, multiple true outputs, a later false result, empty and mixed output, evaluator errors and a cancelled context with benign rules. Use a short test deadline to verify budget propagation without adding a slow test. Run the policy and affected API tests.

## Rollback

Revert the engine and all callers together if needed. Preserve attestation verdicts already recorded. The former evaluator behavior may require re-evaluating affected policy definitions before reuse.
