# Grounding ServiceNow Now Assist with Fides evidence

> Status: implemented (#216, last child of the ServiceNow DevGovOps spoke).
> "Fides advises; ServiceNow decides."

## The problem

When a change manager or CAB member asks **Now Assist** *"is change CHG0030192 safe to
approve?"* or *"what evidence backs this change?"*, a generic LLM will **guess**.
Grounding replaces the guess with Fides's **deterministic, tamper-evident**
control-coverage and evidence, so Now Assist answers from the system of record for
software-delivery evidence instead of hallucinating.

## What Fides provides

A single authoritative **grounding pack** per change request:

**`GET /api/v1/servicenow/grounding?change=CHG0030192`**

```json
{
  "change_number": "CHG0030192",
  "grounded": true,
  "trails": ["<uuid>"],
  "controls_linked": [{"control": "SOC2-CC7.1", "name": "...", "attestation_id": "..."}],
  "coverage": { "total_required": 10, "satisfied": 8, "failed": 1, "missing": 1, "passed": ["..."] },
  "risk": { "score": 25, "level": "medium", "recommendation": "hold", "approved": false },
  "evidence": { "attestations_total": 12, "non_compliant": 0, "by_type": {...}, "tamper_evident": true },
  "grounding_summary": "Change CHG0030192 is linked to 1 Fides control(s): SOC2-CC7.1. Coverage: 8 of 10 required controls have current compliant evidence (1 failing, 1 missing). Change-gate risk: 25/100 (medium); recommendation: HOLD. Evidence: 12 attestation(s), 0 non-compliant; tamper-evidence chain intact. Source: Fides (advisory — ServiceNow decides)."
}
```

- The change → evidence link comes from `change_control_links` (see
  [servicenow-integration.md](servicenow-integration.md), `fides servicenow link-control`).
- `grounding_summary` is a ready-to-quote natural-language statement — the single
  most useful field for grounding.
- A change with **no** linked Fides evidence returns **404** with a `grounding_summary`
  that explicitly says compliance is **UNVERIFIED** (so Now Assist never implies
  evidence exists when it doesn't).

Also exposed via CLI and the Fides MCP server:

```bash
fides servicenow grounding --change CHG0030192
```

`fides-mcp` tool **`ground_change`** (`{ "change_number": "CHG0030192" }`) returns the
same pack — so an AI agent (Claude, Cursor, or ServiceNow's Now Assist via MCP) can
call it directly.

## Wiring it into Now Assist — two options

### Option A — Now Assist Skill calls the grounding API (simplest)

1. Create a **Scripted REST** action or an **IntegrationHub** HTTP step that GETs
   `${fides_base}/api/v1/servicenow/grounding?change=${current.number}` with the
   Fides service-account bearer token (store it in a ServiceNow credential/alias —
   never inline).
2. In your **Now Assist Skill** (Skill Kit) for change summarization/approval,
   add the step's `grounding_summary` (and the structured fields) to the skill's
   **prompt context / grounding input**.
3. Instruct the skill to **only** state compliance conclusions that appear in the
   Fides grounding pack, and to say "compliance unverified by Fides" when the API
   returns `grounded: false`.

Result: Now Assist's change summary and approval guidance are backed by Fides's
signed evidence and risk score.

### Option B — Register Fides as an MCP server (symmetric with #167)

Fides exposes a **remote MCP server over HTTP** (Streamable transport) at:

```
POST https://<fides-host>/api/v1/mcp        # Authorization: Bearer <fides-token>
```

It speaks MCP JSON-RPC (`initialize` / `tools/list` / `tools/call`) and exposes
`ground_change` and `get_controls_coverage`. Register it in ServiceNow's MCP server
registry (`sn_mcp_server`) with a connection + credential alias holding the Fides
bearer token, and Now Assist agents can call `ground_change` as a governed tool —
no scripted fetch. Verify from any MCP client:

```sh
curl -s -X POST https://<fides-host>/api/v1/mcp \
  -H "Authorization: Bearer $FIDES_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"ground_change","arguments":{"change_number":"CHG0032508"}}}'
```

#### Register it in ServiceNow (admin runbook)

Do this in the ServiceNow UI (Connections & Credentials + the MCP Server list) so the
connection validates — the records below are intricate and are best created there,
not via the Table API.

1. **Credential** — *Connections & Credentials → Credentials → New → API key / Bearer*
   (`token_auth_credential`). Store the Fides API token. Name it e.g. `Fides API token`.
2. **Connection** (`http_connection`) — *→ Connections → New*: Connection URL
   `https://<fides-host>/api/v1/mcp`, HTTP method `POST`, attach the credential above so
   requests carry `Authorization: Bearer <token>`. This creates a **Connection alias**
   (`sys_alias`, type *connection*, `http_connection`).
3. **MCP server** (`sn_mcp_server`) — open **`/now/sn-mcp-server/list` → New**: set
   `name` = `Fides MCP server` and `connection_alias` = the alias from step 2.
4. **Now Assist** — in *AI Agent Studio*, add the Fides MCP server's tools (`ground_change`,
   `get_controls_coverage`) to your change-summarization / change-approval agent, and
   instruct it to base compliance statements only on the returned `grounding_summary`.

Once registered, Now Assist calls `ground_change` directly — the grounding pack is a tool
result, not a scripted fetch. (Fides side needs no further change: `/api/v1/mcp` is live.)

> This is the mirror image of [servicenow-mcp.md](servicenow-mcp.md) (Fides consuming
> ServiceNow's MCP server): here ServiceNow consumes Fides's.

## Security

- The grounding endpoint is authenticated with the tenant Fides token and scoped to
  the caller's org (`principalOrg`); it only returns evidence the org owns.
- Store the Fides token in a ServiceNow credential alias, not inline in a script.
- Grounding is **read-only and advisory** — it never changes a change_request.
  ServiceNow remains the decision system of record.

## Worked example (Scripted REST → Now Assist)

A concrete, copy-paste **Scripted REST** resource ServiceNow can call to fetch the
grounding pack. Create a Scripted REST API (e.g. `x_fides/grounding`) with a GET
resource `/{change}` and this script; store the Fides base URL + token in a
**credential/alias** (never inline):

```javascript
(function process(request, response) {
    var change = request.pathParams.change;                 // e.g. CHG0032508
    var base   = gs.getProperty('x_fides.base_url');        // https://fides.../
    var token  = new sn_cc.StandardCredentialsProvider()    // Fides API token (credential alias)
                    .getCredentialByID('fides_api_token').getAttribute('password');

    var r = new sn_ws.RESTMessageV2();
    r.setEndpoint(base + '/api/v1/servicenow/grounding?change=' + encodeURIComponent(change));
    r.setHttpMethod('GET');
    r.setRequestHeader('Authorization', 'Bearer ' + token);
    var res  = r.execute();
    var body = JSON.parse(res.getBody());

    // Feed body.grounding_summary (+ the structured fields) into the Now Assist
    // skill's prompt context. If body.grounded === false, the skill must say
    // "compliance UNVERIFIED by Fides" rather than inventing a conclusion.
    response.setStatus(res.getStatusCode());
    response.setBody(body);
})(request, response);
```

Then in **Now Assist (Skill Kit)**: add this call as a grounding/tool step in your
change-summarization or change-approval skill, and instruct the skill to base every
compliance statement solely on `grounding_summary` / the returned fields.

### Live demo reference
`CHG0032508` on the demo instance is wired end-to-end:
- **Fides → ServiceNow (governed MCP read):** `fides servicenow mcp lookup --table change_request` returns real CRs through SN's MCP governance.
- **ServiceNow change record carries Fides evidence:** a work note ("this change implements control SOC2-CC8.1 … attested via Fides attestation …") and the change **risk field set to Moderate** by the change gate.
- **Now Assist grounding:** `GET /api/v1/servicenow/grounding?change=CHG0032508` → `grounded:true`, **37/37 controls satisfied**, risk 40/100 (medium), recommendation HOLD, tamper-evidence chain intact — the `grounding_summary` is the sentence Now Assist quotes.

Reproduce with `scripts/servicenow-demo.sh` (env-driven; see the script header).

## Related
- [servicenow-integration.md](servicenow-integration.md) — write-back (change gate, control linkage, CMDB anchor).
- [servicenow-mcp.md](servicenow-mcp.md) — Fides consuming ServiceNow's MCP server (#167).
