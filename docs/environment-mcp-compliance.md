# Environment MCP compliance checks

The Environments view can query a live system through an **MCP server** and
evaluate the response against jq rules ("Verify Compliance"). The Fides client
performs a full MCP stdio handshake (`initialize` → `notifications/initialized`
→ `tools/call`), so the configured command must be a **real MCP server** — a
bare `echo` cannot complete the handshake reliably and is not supported.

## The bundled sensor

`fides-mcp-sensor` (built into the server image at
`/usr/local/bin/fides-mcp-sensor`, and allowlisted via
`FIDES_MCP_ALLOWED_COMMANDS`) is a protocol-correct stdio MCP server. Its
`tools/call` response is the JSON from `MCP_SENSOR_RESPONSE`, so each
environment connection supplies its own state snapshot via env vars.

## Configuring a connection

In **Environments → MCP Connections → Add**:

- **Transport**: `stdio`
- **Command**: `/usr/local/bin/fides-mcp-sensor`
- **Env vars**: `MCP_SENSOR_RESPONSE` = the state JSON to evaluate, e.g.
  `{"pods":[{"name":"app","status":"Ready","replicas":1,"readyReplicas":1}]}`
- **Tool name**: `get_pods`
- **jq rules** (one per line), e.g.:

  ```
  .pods[].status == "Ready"
  .pods[].replicas == .pods[].readyReplicas
  ```

"Query State" returns the raw response; "Verify Compliance" additionally
evaluates the rules and reports `compliant` + any `failed_rules`.

## Using a different MCP server

Any real stdio MCP server works — point **Command** at its binary (add it to
`FIDES_MCP_ALLOWED_COMMANDS`) and set **Tool name** to one of its tools. The
allowlist is an RCE guard: only listed binaries are ever executed.
