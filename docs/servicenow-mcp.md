# Fides × ServiceNow MCP — consuming ServiceNow's Model Context Protocol server

> Status: implemented (#167). Fides is an **MCP client** of ServiceNow's GA MCP
> server. Verified against `calitiiltddemo3.service-now.com` (Now Assist / MCP
> Server app installed).

## Why this matters

ServiceNow is the enterprise **system of record** — CMDB configuration items,
change requests, and GRC controls all live there. Fides is the **deterministic
evidence and controls layer** for the software delivery lifecycle. Until now the
two talked one direction (Fides *writes* signed evidence + risk onto change
requests). This makes the link **bidirectional and governed**: Fides now *reads*
from ServiceNow **through ServiceNow's own MCP governance**, not the raw Table
API.

Positioning we take to ServiceNow: **"Fides advises, ServiceNow decides."**
Fides consumes ServiceNow's governed MCP tools, enriches them with tamper-evident
build provenance, and hands the verdict back — ServiceNow's IRM/CMDB/Change
records stay the source of truth. It's a DevSecOps evidence spoke that makes
Now Assist and the CAB **evidence-driven** without moving the system of record.

## What ServiceNow exposes (discovered contract)

ServiceNow's MCP Server app (`sn_mcp_server` scope) presents two surfaces on the
tenant instance:

### 1. GA MCP endpoint (standard MCP protocol)

- **URL pattern:** `https://<instance>.service-now.com/sncapps/mcp-server/mcp/<server>`
- **Servers** are listed in the `sn_mcp_server_registry` table (fields `name`,
  `url`, `status`). On the demo instance the active server is
  `sn_mcp_server_default`.
- **Transport:** MCP **Streamable HTTP** — JSON-RPC POSTs; the server may reply
  with `application/json` or a `text/event-stream` (SSE) frame. A session id is
  carried in the `Mcp-Session-Id` header.
- **Auth:** **OAuth 2.0 bearer** (the endpoint 302-redirects browser/basic-auth
  requests to SSO). This is the endpoint external MCP clients (Claude, Fides)
  connect to.

### 2. Governed scripted-REST facade (`/api/sn_mcp_server/...`)

Used for direct, governed record access. Accepts the same auth as the Table API
(basic **or** OAuth):

| Operation | Method + path | Purpose |
|---|---|---|
| Governed record lookup | `POST /api/sn_mcp_server/mcp_lookup_service/get_records` | Find records in any table (CMDB CIs, change requests, GRC controls) matching a query |
| Generic tool executor | `POST /api/sn_mcp_server/mcp_tools_api/generic_tool_executor` | Invoke a governed MCP tool by `artifact_id` |
| List a server's tools | `GET /api/sn_mcp_server/mcp_tools_api/tools/server/{name}` | Tool catalogue for a server |

`get_records` returns matched record **identifiers + count** for a `{table, query,
limit}` body — a discovery primitive (which records match), governed by SN.

## What Fides implements

| Layer | File |
|---|---|
| Generic MCP **Streamable HTTP** client (initialize → tools/list → tools/call, session id, SSE) | `pkg/mcp/http.go` |
| ServiceNow MCP client (server discovery, governed lookup, session) | `pkg/servicenow/mcp.go` |
| API endpoints | `pkg/api/servicenow_mcp.go` |
| CLI | `fides servicenow mcp <servers\|lookup\|tools\|call>` |

Auth reuses the existing tenant ServiceNow config (`basic` or `oauth2`), so no
new secret plumbing.

### API

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/servicenow/mcp/servers` | Discover provisioned MCP servers (from `sn_mcp_server_registry`) |
| `POST /api/v1/servicenow/mcp/lookup` `{table,query,limit}` | Governed record lookup (CMDB / change / GRC) |
| `POST /api/v1/servicenow/mcp/tools` `{server}` | List a GA MCP server's tools |
| `POST /api/v1/servicenow/mcp/call` `{server,tool,arguments}` | Invoke a governed MCP tool |

### CLI

```bash
# Discover the MCP servers on the instance
fides servicenow mcp servers

# Governed reads — through ServiceNow's MCP layer, not the raw Table API
fides servicenow mcp lookup --table change_request        --query "active=true" --limit 5
fides servicenow mcp lookup --table cmdb_ci_service        --query "operational_status=1"
fides servicenow mcp lookup --table sn_compliance_control  --limit 10   # GRC controls

# Standard MCP protocol (GA endpoint — needs OAuth, see setup)
fides servicenow mcp tools  --server sn_mcp_server_default
fides servicenow mcp call   --server sn_mcp_server_default --tool <tool> --args '{"k":"v"}'
```

## Setup & configuration

### 1. Prerequisites on the ServiceNow side

- The **MCP Server** capability (part of Now Assist / AI Agents) must be
  installed. Verify at `/now/sn-mcp-server/list`, or:
  ```bash
  curl -u "$SN_USER:$SN_PASS" \
    "$SN_URL/api/now/table/sn_mcp_server_registry?sysparm_fields=name,url,status"
  ```
  At least one server should show `status=active` (e.g. `sn_mcp_server_default`).
- The service account needs read access to the tables you intend to look up
  (`change_request`, `cmdb_ci*`, `sn_compliance_control`, …) and to
  `sn_mcp_server_registry`.

### 2. Auth: OAuth vs basic

- The **governed facade** (`fides servicenow mcp lookup`, and `mcp servers`)
  works with either **basic** or **oauth2** — whatever the tenant is configured
  with. This is the fastest path to value and needs no new setup.
- The **GA MCP endpoint** (`mcp tools` / `mcp call`) requires **OAuth 2.0**. To
  enable it:
  1. In ServiceNow: **System OAuth → Application Registry → New → Create an OAuth
     API endpoint for external clients**. Record the **Client ID** and **Client
     Secret**.
  2. Grant the OAuth app / integration user the MCP roles (e.g.
     `sn_mcp_server.user`) and table read ACLs.
  3. Configure Fides with OAuth (below).

> Fides never stores the secret inline — it takes a **secret reference**
> (`--secret-path`) resolved via the secrets provider (env var or AWS Secrets
> Manager). See [servicenow-integration.md](servicenow-integration.md).

### 3. Configure Fides

```bash
# OAuth2 (enables the full MCP protocol path)
fides servicenow config \
  --instance-url https://<instance>.service-now.com \
  --auth-type oauth2 \
  --client-id  <oauth_client_id> \
  --secret-path SN_OAUTH_CLIENT_SECRET      # env var / Secrets Manager id

# — or — Basic (governed lookup + server discovery only)
fides servicenow config \
  --instance-url https://<instance>.service-now.com \
  --auth-type basic \
  --client-id  <service_account_user> \
  --secret-path SN_SERVICE_ACCOUNT_PASSWORD
```

### 4. Verify

```bash
fides servicenow mcp servers                              # should list active servers
fides servicenow mcp lookup --table change_request --limit 1
# With OAuth configured:
fides servicenow mcp tools --server sn_mcp_server_default
```

## Security

- **SSRF guard:** every ServiceNow URL (instance, MCP endpoint, OAuth token) is
  validated to be HTTPS and non-loopback/non-private (`validateInstanceURL`).
- **Least privilege:** use a dedicated integration/OAuth identity with read-only
  ACLs on the target tables.
- **No raw secrets in config:** credentials are secret references, resolved at
  request time.
- **Governed reads:** lookups go through ServiceNow's MCP lookup service, so
  ServiceNow's ACLs/policies still apply — Fides cannot read what the identity
  isn't entitled to.

## How this makes ServiceNow better (the story for SN)

1. **Evidence-driven CAB / Now Assist** — Fides feeds tamper-evident build
   provenance, SLSA/cosign/SBOM evidence, and a 0–100 risk score onto the exact
   change records the CAB reviews, and can now *read back* CMDB CIs and GRC
   controls through SN's governance to close the loop.
2. **Continuous Controls Monitoring** — Fides maps deterministic delivery
   evidence to GRC controls (`sn_compliance_control`) and keeps them current,
   without Fides ever becoming the controller.
3. **Bidirectional and governed** — reads honour ServiceNow ACLs (via the MCP
   lookup service); writes land on `change_request` / CMDB CIs. ServiceNow stays
   the system of record.

## Related

- [servicenow-integration.md](servicenow-integration.md) — the write-back side
  (change gate, control linkage, CMDB anchoring).
- [mcp-server.md](mcp-server.md) — the *other* direction: Fides' own `fides-mcp`
  server that exposes Fides data to Claude/Cursor.
