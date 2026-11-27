---
status: approved
issue: 541
author: olafkfreund
---

# Intent: Apply the public HTTPS policy throughout outbound delivery

## Problem

The #523 outbound audit found that the webhook and ServiceNow public HTTPS policy needs to hold across the complete HTTP operation.

## Proposed outcome

Configured public HTTPS requests and allowed redirects work. Disallowed addresses and redirects fail before delivery.

## Affected users and systems

Fides event webhooks and ServiceNow integration clients, including authenticated requests.

## Constraints

Retain normal delivery, response handling, retries, timeouts, and allowed same-origin HTTPS redirects. Use isolated synthetic fixtures.

## Open questions

None.
