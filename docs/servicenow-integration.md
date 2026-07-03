# ServiceNow Integration

Fides integrates with ServiceNow across four surfaces, all driven by the
event/outbox core and opt-in via `FIDES_EVENTS_ENABLED=true`:

| Surface | What it does | Mechanism |
|---|---|---|
| **CMDB** | Upserts running services/images/containers as CIs | IRE (`/api/now/identifyreconcile`), `snapshot.reported` → `CMDBSink` |
| **ITOM** | Alerts on shadow deployments & runtime drift | Event Management (`/api/global/em/jsonv2`), `snapshot.noncompliant` → `ITOMSink` |
| **ITSM** | Gates deploys on an approved change request | Table API (`change_request`), `POST /api/v1/servicenow/change-check` |
| **CMDB anchoring** | Attaches a signed deployment attestation to the CI on change close / deploy | Attachment API (`/api/now/attachment/file`), `deployment.attested` → `CMDBSink` |
| **MCP** | Dev-agent tools for change status / incidents / CMDB | `fides-mcp` tools → Fides endpoints → Table API |

## 1. ServiceNow service account & roles

Create a dedicated integration user and grant least-privilege roles per surface:

- **CMDB (IRE)**: `import_transformer` (and `itil` for read).
- **ITOM (Event Management)**: `evt_mgmt_integration` / `sn_event_read` (write to `em_event`).
- **ITSM (Table API)**: `itil` (read `change_request`, create `incident`).
- **CMDB read (MCP search)**: `cmdb_read` / `itil`.

Prefer **OAuth2** over Basic where possible. For OAuth2 client-credentials,
register an OAuth application (System OAuth → Application Registry) and use its
`client_id`/`client_secret`. Basic auth uses the service account's
username/password.

## 2. Store the credential

The credential is never stored in the Fides database — only a `secret_path`
reference, resolved at use time by the secrets provider:

- `SECRETS_PROVIDER=env` (default): `secret_path` is an environment variable name.
- `SECRETS_PROVIDER=aws`: `secret_path` is an AWS Secrets Manager secret id
  (region from `AWS_REGION`).

## 3. Configure the tenant

```bash
curl -X POST https://<fides>/api/v1/tenant/servicenow \
  -H "Authorization: Bearer $FIDES_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "instance_url": "https://acme.service-now.com",
    "auth_type": "oauth2",          # or "basic"
    "client_id": "<oauth client id or basic username>",
    "secret_path": "SNOW_SECRET",   # env var / Secrets Manager id holding the secret
    "enabled": true
  }'
```

The instance URL must be `https` and is SSRF-guarded (loopback/private/
link-local addresses are rejected).

## 4. Enable the integration

Set `FIDES_EVENTS_ENABLED=true` on the Fides server. The dispatcher then runs
the webhook, commit-status, **ServiceNow ITOM**, and **ServiceNow CMDB** sinks.
Snapshots emit `snapshot.reported` (CMDB) and, when non-compliant,
`snapshot.noncompliant` (ITOM).

### ITOM severity mapping

`em_event.severity` is `0=Clear, 1=Critical, 2=Major, 3=Minor, 4=Warning,
5=Info`. Fides maps **ShadowDeployment → 1 (Critical)** and **RuntimeDrift → 3
(Minor)**, each with a stable `message_key` so repeated snapshots update the
same alert instead of creating new ones.

## 5. ITSM change-control gate

1. Seed the `servicenow-change` attestation type (see
   `servicenow-change-type.example.sql`) with jq rules, e.g. approved + in
   implement/scheduled + not on hold + risk ≠ high.
2. In CI, before deploying, call the gate:

   ```bash
   curl -X POST https://<fides>/api/v1/servicenow/change-check \
     -H "Authorization: Bearer $FIDES_API_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"trail_id":"'$TRAIL_UUID'","change_number":"CHG0030192"}'
   ```

   It fetches the CR, evaluates the jq rules, records a `servicenow-change`
   attestation on the trail, and emits `compliance.evaluated` — so `fides
   assert` and the GitHub/GitLab commit-status gate both reflect it.

## 6. Change↔Control linkage

Gating a deploy on an approved change (§5) proves the change happened; it
doesn't record *which control* the change satisfied, or *what evidence*
proved it. `link-control` closes that gap: it records, on the Fides side,
that change `CHGxxxx` implemented control `<key>` via a specific attestation
(evidence) at a point in time — then writes that same reference back onto the
ServiceNow `change_request` (a work note, plus best-effort `u_fides_control` /
`u_fides_attestation_id` / `u_fides_attested_at` fields if your instance has
added them), so an auditor reading the change in ServiceNow can trace
straight to the Fides evidence.

```bash
fides servicenow link-control \
  --trail "$TRAIL_UUID" \
  --change CHG0030192 \
  --control SOC2-CC7.1
  # --attestation <id> optional — defaults to the trail's most recent attestation
```

or via the API:

```bash
curl -X POST https://<fides>/api/v1/servicenow/link-control \
  -H "Authorization: Bearer $FIDES_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"trail_id":"'$TRAIL_UUID'","change_number":"CHG0030192","control":"SOC2-CC7.1"}'
```

The Fides-side linkage (`change_control_links`) is always persisted, even if
ServiceNow is unreachable or unconfigured — the response's
`servicenow_written` field (plus `servicenow_message` when `false`) reports
whether the change_request write-back succeeded, so pipelines can gate on the
Fides record regardless of ServiceNow availability. Re-linking the same
trail/control/change upserts in place (idempotent).

## 7. CMDB deployment anchoring (change close / deploy)

Proves the artifact that was actually deployed matches change intent by
attaching the signed deployment attestation — image digest, commit, build log
ref, and runtime snapshot ref — to the relevant CMDB CI:

```bash
curl -X POST https://<fides>/api/v1/servicenow/deployment-anchor \
  -H "Authorization: Bearer $FIDES_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"trail_id":"'$TRAIL_UUID'","change_number":"CHG0030192","build_log_ref":"https://ci.example.com/builds/42"}'
```

or via the CLI:

```bash
fides servicenow anchor-deployment --trail $TRAIL_UUID --change CHG0030192 \
  --build-log https://ci.example.com/builds/42
```

The CI is resolved from the change request's `cmdb_ci` reference (preferred —
it's what the change actually authorized), or by name via `--ci`/`ci`. Fides:

1. Records a `deployment_anchors` row — Fides-side evidence of the anchor,
   independent of ServiceNow reachability, including the trail's attestation
   `content_hash` (tying it into the trail's tamper-evidence chain).
2. When `FIDES_EVENTS_ENABLED=true`, enqueues `deployment.attested`, delivered
   by the same `CMDBSink` that reconciles snapshots: it uploads the attestation
   as a CI attachment via the Attachment API and posts a short summary onto the
   CI record.

## 8. MCP tools (developer agents)

`fides-mcp` exposes:

- `get_change_request_status` — `GET /api/v1/servicenow/change-status`
- `create_compliance_incident` — `POST /api/v1/servicenow/incident`
- `search_cmdb_ci` — `GET /api/v1/servicenow/cmdb`

## 9. DevGovOps spoke (packaging artifacts)

ServiceNow-side packaging artifacts — a signature-verifying Scripted REST API, an
IntegrationHub spoke / Flow Designer action spec, and a Now Assist grounding
guide — live under [`servicenow/`](servicenow/) (epic #216):

- [`servicenow/hmac-webhook-verification.md`](servicenow/hmac-webhook-verification.md)
  — verify the Fides `X-Fides-Signature` HMAC on inbound webhooks (#229).
- [`servicenow/flow-designer-actions.md`](servicenow/flow-designer-actions.md)
  — "Attach Fides evidence", "Require Fides gate", "Anchor deployment in CMDB" (#232).
- [`servicenow/now-assist-grounding.md`](servicenow/now-assist-grounding.md)
  — ground Now Assist change-risk predictions on signed Fides evidence (#233).

## Testing

- Per-component behaviour (REST client, ITOM/CMDB sinks, change normalization)
  is covered by `pkg/servicenow` unit tests against an httptest mock.
- `DBLoader` config resolution is covered by a Postgres-backed integration test
  (`pkg/servicenow`, gated by `FIDES_TEST_DB_DSN`), run in CI.
