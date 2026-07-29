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
      "env": {
        "FIDES_SERVER_URL": "https://fides.your-domain.com",
        "FIDES_API_TOKEN": "<service-account API key>"
      }
    }
  }
}
```

Create the API token in the portal: **Settings → Service Accounts → Create →
Issue key** (Auditor role is enough for read-only querying).

## Tools

| Tool | What it does |
|------|--------------|
| `list_flows` / `list_environments` / `list_policies` | List pipelines, runtime environments, and policies |
| `check_compliance` | Check an artifact SHA256 against policy rules |
| `search_artifacts` | Find artifacts by name / SHA prefix / git commit |
| `search_attestations` | Find attestations by evidence type / compliance status |
| `get_controls_coverage` | Governance controls + per-environment coverage |
| `get_deployment_frequency` | Weekly deployment frequency per environment |
| `create_flow` / `create_trail` / `report_artifact` / `report_attestation` | Record provenance from an agent |
| `get_change_request_status` / `create_compliance_incident` / `search_cmdb_ci` | ServiceNow change/incident/CMDB |

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

**Read-only**

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

**Safe actions**

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
