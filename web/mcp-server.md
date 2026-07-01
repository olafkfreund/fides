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

## Try it in Claude Code

> "Using the fides tools, list our environments and their controls coverage, then
> read the getting-started doc and summarize how to record an attestation."
