---
status: draft
issue: 526
author: olafkfreund
---

# Intent: Queue evidence locally during a recording outage

## Problem

Fides losing connectivity can fail CI even when a job only records evidence. When a request has an ambiguous outcome, a later retry may also duplicate the evidence.

## Proposed outcome

Operators can opt into fail-open recording for supported commands. During eligible failures, the CLI warns, durably queues the request and returns success only after persisting it. Replay preserves required ordering and retains entries until confirmed. Gates retain fail-closed defaults, and any supported override is auditable.

## Affected users and systems

Fides CLI, CI runners, evidence recording and gating endpoints.

## Constraints

Protect queued evidence, authentication material and attachments. Provide destination and tenant binding, replay deduplication and visible failure when the spool cannot be written.

## Open questions

Confirm which recording and gate override commands are in scope, and how ephemeral runners retain a queue for replay.
