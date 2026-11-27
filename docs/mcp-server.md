---
layout: default
redirect_from:
  - /mcp-server.html
---

# Fides MCP Server (`fides-mcp`)

Fides ships a **Model Context Protocol** server, `fides-mcp`, so AI tools like
**Claude Code**, Claude Desktop, and Cursor can query your compliance data and
read the Fides documentation directly in a conversation.

It is a stdio binary that the AI client spawns; it talks to your Fides API over
`FIDES_SERVER_URL` and authenticates with a service-account key.

## Build

```bash
go build -o fides-mcp ./cmd/mcp
# it is also shipped in the server image at /usr/local/bin/fides-mcp
```

## Configure Claude Code

Add to your project's `.mcp.json` (or the Claude Code MCP settings):

```json
{
  "mcpServers": {
    "fides": {
      "command": "/absolute/path/to/fides-mcp",
      "args": ["--read-only"],
      "env": {
        "FIDES_SERVER_URL": "https://fides.your-domain.com",
        "FIDES_API_TOKEN": "<read-only service-account API key>"
      }
    }
  }
}
```

Upgrade every API server serving the Fides URL before issuing scoped keys.
If automatic migrations are disabled, apply
`0031_service_account_key_read_only.sql` before starting the new servers.
As a tenant Admin, create a Viewer service account and set
`VIEWER_ACCOUNT_ID` to its returned ID before issuing the key.

```bash
fides service-account create --name mcp-assistant --role Viewer
fides service-account issue-key --account "$VIEWER_ACCOUNT_ID" --read-only
```

Use the issued key as `FIDES_API_TOKEN`. Check that the response shows
`"read_only": true`. The API limits the key to the read endpoints needed by MCP.
Keep the key out of version control.

Before rolling back, list each service account's keys with
`GET /api/v1/tenant/service-accounts/{id}/keys`. Revoke every active key with
`"read_only": true` using
`fides service-account revoke-key --account "$ACCOUNT_ID" --key "$KEY_ID"`.

## Read-only and write access

Read-only mode lists only read tools and rejects direct calls to write tools.
Set `--read-only` or `FIDES_MCP_READ_ONLY=true` to enable it. An explicit flag
takes precedence over the environment setting.

Existing configurations keep their write-capable tool list unless you enable
read-only mode. ServiceNow change status and CMDB search require a write-capable
session because they can request a ServiceNow OAuth token. ServiceNow grounding
remains available in read-only mode.

For a client that needs writes, set `--read-only=false` and use
a separate credential with the required role. Configure the client to request
approval for write calls. MCP tool annotations describe tool behavior to the
client. The server and API enforce access independently.

## Tools

| Tool | What it does |
|------|--------------|
| `list_flows` / `list_environments` / `list_policies` | List pipelines, runtime environments, and policies |
| `check_compliance` | Check recorded control verdicts for an artifact using `artifact_sha256` |
| `search_artifacts` | Find artifacts by name / SHA prefix / git commit |
| `search_attestations` | Find attestations by evidence type / compliance status |
| `get_controls_coverage` | Governance controls + per-environment coverage |
| `get_deployment_frequency` | Weekly deployment frequency per environment |
| `create_flow` / `create_trail` / `report_artifact` / `report_attestation` | Record provenance from an agent |
| `get_change_request_status` / `create_compliance_incident` / `search_cmdb_ci` | ServiceNow change/incident/CMDB |

`report_attestation` accepts the optional legacy `is_compliant` argument as a
deprecated input. Fides ignores it and calculates the verdict on the server.

## Resources (documentation)

`fides-mcp` exposes the Fides docs as MCP **resources**, so the assistant can read
them on demand (`resources/list` + `resources/read`):

- `fides://docs/getting_started` — self-hosting & first flow
- `fides://docs/features` — full feature overview
- `fides://docs/cli-reference` — the `fides` CLI
- `fides://docs/environment-mcp-compliance` — runtime MCP compliance
- `fides://docs/servicenow-integration` — ServiceNow
- `fides://docs/aws-secrets-manager` — secrets
- `fides://docs/architecture_proposal` — architecture

## In-browser WebMCP

Separately from the standalone `fides-mcp` server, the **Fides portal registers
its capabilities with the browser's WebMCP surface**. This lets
browser-integrated AI agents and local LLMs/assistants drive Fides directly from
the page, using the **logged-in session** — no separate server or token needed.

### Transport

The portal prefers the native **W3C `document.modelContext.registerTool(...)`**
API where the browser exposes it (currently a Chrome origin trial). Where that is
unavailable, it falls back to the [`@mcp-b/global`](https://www.npmjs.com/package/@mcp-b/global)
polyfill (`navigator.modelContext`). If the browser supports neither, registration
**no-ops** — the portal keeps working normally.

Registration happens **automatically once the portal is authenticated**; there is
nothing to install or configure.

### Tools exposed

Each tool calls the **same-origin, cookie-authenticated** Fides API using the
current user's session, so an agent only sees what the signed-in user is allowed
to see.

#### Read-only

| Tool | What it does |
|------|--------------|
| `fides_list_flows` | List pipelines |
| `fides_list_environments` | List runtime environments |
| `fides_list_policies` | List policies |
| `fides_controls_coverage` | Governance controls + per-environment coverage |
| `fides_search_artifacts` | Find artifacts by name / SHA prefix / git commit |
| `fides_search_attestations` | Find attestations by evidence type / compliance status |
| `fides_deployment_frequency` | Weekly deployment frequency per environment |
| `fides_compliance_summary` | Overall compliance summary |

#### Safe actions

| Tool | What it does |
|------|--------------|
| `fides_enforce_control` | Enforce a control (`control` + `environment_id`, or `all`) |
| `fides_import_framework` | Import a controls `framework` |

### WebMCP vs. the `fides-mcp` server

| | `fides-mcp` server | In-browser WebMCP |
|---|---|---|
| Where it runs | Standalone MCP server (stdio binary) | Inside the portal browser tab |
| Clients | Claude Code, Claude Desktop, Cursor | Browser-integrated AI agents, local LLMs/assistants |
| Auth | Service-account API token (`FIDES_API_TOKEN`) | The user's existing portal session (cookie) |
| Setup | Configure `.mcp.json` + issue a key | Automatic once you're logged in |

## Try it in Claude Code

> "Using the fides tools, list our environments and their controls coverage, then
> read the getting-started doc and summarize how to record an attestation."
