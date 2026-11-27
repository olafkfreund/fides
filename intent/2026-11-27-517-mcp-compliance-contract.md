---
status: draft
issue: 517
author: olafkfreund
---

# Intent: Align the compliance clients with the API

## Problem

The MCP tool sends artifact_sha256 as an HTTP query key while the compliance endpoint requires sha256. The CLI assert command reads the response body without checking HTTP status, and the API ignores the CLI policy selector and the MCP attestation verdict field.

## Proposed outcome

MCP sends the HTTP key the API expects while retaining its existing tool argument. CLI assert distinguishes a failed request from a valid non-compliance verdict. Every advertised input has documented behavior, and tests cover the request contract and status handling.

## Affected users and systems

cmd/mcp, cmd/cli, the compliance API and attestation ingestion.

## Constraints

Keep verdict computation on the server. Preserve the existing digest-wide behavior when callers supply no policy selector.

## Open questions

Should assert implement named-policy selection or visibly reject the currently unsupported flag? Determine the compatibility treatment for the redundant MCP verdict argument.
