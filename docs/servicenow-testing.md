# Testing the ServiceNow integration

How to exercise every ServiceNow surface against a real instance, and how to
verify in ServiceNow that what Fides claims it did actually happened.

Written from doing it against `calitiiltddemo3.service-now.com` on 2026-08-17.
The failures described below are the ones that were actually found, not
anticipated ones — and the first run found a defect that had been shipping
silently for months.

## Why mocks were not enough

`pkg/servicenow` had 31 unit tests, all passing, all green in CI. Every one of
them stands up an `httptest.Server` and asserts that Fides sent well-formed
JSON. That is worth having: it covers OAuth token caching, 5xx retry/backoff,
the SSRF guard on the instance URL, and the IRE payload shape.

But a mock accepts whatever you send it. Those tests prove **Fides speaks**.
They cannot prove **ServiceNow understands**.

The gap was not theoretical. The CMDB sink was posting an IRE payload that
ServiceNow rejected *in full*, and reporting success every time, because:

```
POST /api/now/identifyreconcile   ->   HTTP 200
{"result":{"hasError":true,"items":[{"errors":[
  {"error":"INVALID_INPUT_DATA",
   "message":"In payload invalid data source [null] exist..."}]}]}}
```

**IRE answers HTTP 200 even when it commits nothing.** The transport succeeded,
so `doJSON` returned nil, so the sink returned nil, so the outbox marked the
event delivered. Fides reported healthy CMDB sync while ServiceNow created zero
CIs. Three separate defects were stacked in that one call:

| Defect | Symptom | Fix |
|---|---|---|
| No discovery source | `INVALID_INPUT_DATA` on every item | `sysparm_data_source` **query param** (in the body it is ignored) |
| `Instantiated From` is not a relationship | `No such relationship ... in cmdb_rel_type` | `Instantiates::Instance of`, and the image is the **parent** |
| CI classes identified by fields Fides never sent | `MISSING_MATCHING_ATTRIBUTES` | send `image_id` and `container_id` |

No mock-based test could have caught any of them, because the mock returned
`200` and the assertions stopped there.

**The rule this produces:** every live check must end in a read-back through
ServiceNow's own Table API. A 200 from Fides only proves Fides was happy.

## Running the live suite

```bash
export FIDES_SERVER_URL=https://fides.<host>
export FIDES_API_TOKEN=...          # org-scoped
export FIDES_FLOW_ID=...            # a flow with at least one trail
export SN_URL=https://<instance>.service-now.com
export SN_USER=... SN_PASS=...

./scripts/servicenow-e2e.sh
```

It exits with the number of failed checks, so CI can gate on it. Nothing is
auto-deleted; the run prints the records it created so they can be cleaned up
or inspected.

Each check drives a surface and then asks ServiceNow what happened:

| # | Surface | Driven by | Verified in ServiceNow by |
|---|---|---|---|
| 0 | credential + roles | Table API probe per surface | HTTP 200 on each table |
| 1 | CMDB IRE | `POST /api/now/identifyreconcile` | CIs exist in `cmdb_ci_*`; **relations exist in `cmdb_rel_ci` with the right type and direction** |
| 2 | ITOM | `POST /api/global/em/jsonv2` | row in `em_event` matching `message_key` (polled — ingestion is async) |
| 3 | Change check | `POST /api/v1/servicenow/change-check` | attestation recorded; CR state read back |
| 4-5 | Gate write-back + control link | `POST …/link-control` | `sys_journal_field` work note names the control and attestation UUID |
| 6 | Anchoring | Attachment API | `sys_attachment` row with non-zero `size_bytes` |
| 7 | Grounding | `GET …/grounding` | `grounded` true, summary cites real control keys |
| 8 | Governed MCP lookup | `POST …/mcp/lookup` | row count agrees with a direct Table API query |

Relations get their own assertions because they fail *independently* of the
items — a relation whose type is not a `cmdb_rel_type` name is rejected on its
own, which is exactly how `Instantiated From` went unnoticed.

## Prerequisites on the instance

**The discovery source must be a valid choice.** IRE validates
`sysparm_data_source` against the choice list of `cmdb_ci.discovery_source` and
rejects everything if it does not match. Fides defaults to `Other Automated`,
which is out-of-box on every instance.

For a CMDB that attributes CIs to Fides specifically — worth having, since it
makes "which CIs came from Fides" a one-field query — add a `Fides` choice and
point Fides at it:

```
System Definition > Choice Lists > new
  Table: cmdb_ci     Element: discovery_source     Value/Label: Fides
```

```bash
FIDES_SNOW_DISCOVERY_SOURCE=Fides   # on the server
```

List the valid choices on any instance with:

```bash
curl -sS -G -u "$SN_USER:$SN_PASS" \
  --data-urlencode 'sysparm_query=name=cmdb_ci^element=discovery_source' \
  --data-urlencode 'sysparm_fields=value' \
  "$SN_URL/api/now/table/sys_choice"
```

**Event Management is not on a stock instance.** `com.glideapp.itom.snac`
requires a separate subscription; on a Personal Developer Instance it must be
requested through the developer portal (Manage → Instance → Action → Activate
Plugin). Confirm before relying on surface 2:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -u "$SN_USER:$SN_PASS" \
  "$SN_URL/api/now/table/em_event?sysparm_limit=1"      # 200 = present
```

## Testing the ServiceNow-side half

The inbound spoke — the `Fides Inbound` Scripted REST API and the
`FidesWebhookVerifier` Script Include from
[`servicenow/update-set`](servicenow/update-set/) — runs *inside* ServiceNow.
No Go test can execute it.

Use the **Automated Test Framework**. The `Send REST Request - Inbound` step
fires a real payload at the endpoint, and `Assert Status Code` verifies the
response. Three tests cover the verifier:

| Test | Payload | Expect |
|---|---|---|
| Valid signature | body + correct `X-Fides-Signature` | 200, record created |
| Tampered body | body altered, signature unchanged | 401 |
| Missing header | no `X-Fides-Signature` | 401 |

The second one matters most: without it, a verifier that unconditionally
returns `true` passes the first test.

ATF tests are records, so they ship **in the same update set as the code they
test** — the spoke then arrives at a customer carrying its own proof.

## Least privilege is not proven by a green run

On `calitiiltddemo3` the integration user (`github_integration`) holds
**`admin`**. Every surface therefore passes regardless of whether the
per-surface roles in [servicenow-integration.md](servicenow-integration.md) are
sufficient.

A green suite run against an admin account proves the *payloads* are right. It
does not prove the *documented role set* is right. To test that, create a
second service account with only the listed roles and run the suite again —
until then, treat the role table as a design intent rather than a verified
claim.

## What "done" looks like

```
== Result: 18 passed, 0 failed
```

If something fails, the failure names the surface. The two that historically
break are CMDB (a payload/identify-rule mismatch, which shows in the IRE error
text) and ITOM (the plugin is not activated, which shows as a non-200 on
`em_event` in the preflight).

## See also

- [ServiceNow Integration](servicenow-integration.md) — the surfaces and their setup
- [DevGovOps spoke](servicenow/README.md) — the ServiceNow-side artifacts
- [HMAC webhook verification](servicenow/hmac-webhook-verification.md) — what the ATF tests above cover
