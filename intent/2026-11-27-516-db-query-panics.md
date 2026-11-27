---
status: draft
issue: 516
author: olafkfreund
---

# Intent: Return database query failures without panicking

## Problem

A failed database query can panic the integration event dispatcher, the environment list, or either of two AI assistant commands. The dispatcher runs in a server goroutine, so its panic can take the server down. A failed environment or assistant query can also leave callers without a valid response.

## Proposed outcome

- A failed batch claim returns the database error with zero events processed and leaves the server running.
- The environment list and the assistant commands for listing flows and finding failing trails return the existing HTTP 500 response if the affected query fails, before emitting any success response.
- Successful queries preserve existing behavior. Result sets are released before dispatching to sinks or issuing subsequent queries on a request-scoped connection.
- A regression test drives a failed batch claim through `DispatchBatch` and asserts the returned error.

## Affected users and systems

Background integration delivery, the environment API and portal, and the AI assistant's database-backed commands.

## Constraints

Keep the change scoped to the four reported sites and their result-set cleanup. Outbox delivery semantics, pagination and handler refactoring are tracked separately in #519, #520 and #522.

## Open questions

None.
