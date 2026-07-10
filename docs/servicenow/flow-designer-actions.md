# Fides IntegrationHub spoke — Flow Designer actions

> Closes [#232](https://github.com/olafkfreund/fides/issues/232). Part of epic
> [#216](https://github.com/olafkfreund/fides/issues/216).

Package the Fides → ServiceNow integrations as an **IntegrationHub spoke** so
ServiceNow admins adopt them with no code: drag Fides actions into any flow. This
spec defines the three headline actions, their inputs/outputs, and the exact
Fides REST steps each one runs. All endpoints below **already exist** in
[`pkg/api/server.go`](https://github.com/olafkfreund/fides/blob/main/pkg/api/server.go); the signed-bundle enrichments they
carry land via sibling PRs #226 (evidence bundle + risk), #227 (change↔control
linkage), and #228 (CMDB provenance).

An importable **update-set skeleton** is in
[`update-set/fides_spoke_update_set.xml`](update-set/fides_spoke_update_set.xml).

## Spoke connection

One **Connection & Credential alias** `x_fides.api`:

- **Base URL:** `https://<fides>` (your Fides server, e.g. `https://fides.13.134.88.9.nip.io`)
- **Credential:** API token in the `Authorization: Bearer <token>` header.
- Every action REST step targets this alias and adds
  `Content-Type: application/json`.

Provision a Fides **service account** token for the spoke (least privilege — read
trails/controls, write change-gate). See
[`docs/servicenow-integration.md`](../servicenow-integration.md) §1 for the
mirror-image ServiceNow service account.

---

## Action 1 — "Attach Fides evidence to change"

Writes the evidence-backed **change-gate verdict + 0–100 risk score** onto a
ServiceNow Change Request as a work note and the `risk` field. Fides advises,
ServiceNow decides.

**Inputs**

| Name | Type | Required | Notes |
|---|---|---|---|
| `trail_id` | String (UUID) | yes | The Fides trail for the build/deploy under change |
| `change_number` | String | yes | e.g. `CHG0030192` |

**Outputs**

| Name | Type | Notes |
|---|---|---|
| `written` | Boolean | true when the CR was updated |
| `sys_id` | String | the CR sys_id that was updated |
| `recommendation` | String | `approve` \| `hold` |
| `risk_score` | Integer | 0–100 |
| `gate` | Object | full verdict (passed/failed/missing_evidence/approvals) |

**REST step** — `POST {{base}}/api/v1/servicenow/change-gate`

```json
{ "trail_id": "{{inputs.trail_id}}", "change_number": "{{inputs.change_number}}" }
```

This endpoint ([`servicenow_change_gate.go`](https://github.com/olafkfreund/fides/blob/main/pkg/api/servicenow_change_gate.go))
computes the gate, then updates `change_request` — mapping Fides risk to the
ServiceNow `risk` field (`high→2`, `medium→3`, `low→4`) and posting a work note —
in one call. Map the JSON response fields straight to the action outputs. The
signed evidence bundle (chain verdict, artifact digests, attestation summary)
attaches here once #226 merges.

---

## Action 2 — "Require Fides gate"

A **guard** action for approval/deploy flows: it reads the trail's change-gate and
**fails the flow step** unless Fides recommends approval, so a CR cannot advance
without passing controls, evidence, and a human sign-off (segregation of duties).

**Inputs**

| Name | Type | Required | Notes |
|---|---|---|---|
| `trail_id` | String (UUID) | yes | The Fides trail to gate on |
| `max_risk_score` | Integer | no | Fail if `risk_score` exceeds this (default 0 = require `approve`) |

**Outputs**

| Name | Type | Notes |
|---|---|---|
| `passed` | Boolean | true only if the gate allows the change |
| `recommendation` | String | `approve` \| `hold` |
| `risk_score` | Integer | 0–100 |
| `summary` | String | human-readable reason |

**REST step** — `GET {{base}}/api/v1/trails/{{inputs.trail_id}}/change-gate`

Response ([`change_gate.go`](https://github.com/olafkfreund/fides/blob/main/pkg/api/change_gate.go), `computeChangeGate`):

```json
{
  "approved": true,
  "recommendation": "approve",
  "risk_score": 0,
  "risk_level": "low",
  "passed": ["SOC2-CC8.1"],
  "failed": [],
  "missing_evidence": [],
  "approvals": { "count": 2, "human_approvers": 2, "four_eyes": true },
  "summary": "All controls satisfied ... safe to approve."
}
```

**Post-step script** (spoke action logic): set `passed = (recommendation ==
'approve') && (risk_score <= max_risk_score)`; if not `passed`, mark the flow
step failed / throw so the surrounding approval flow halts. Optionally chain
Action 1 to write the failing verdict back onto the CR for the CAB to see.

---

## Action 3 — "Anchor deployment in CMDB"

On change close, attach the **signed deployment attestation** (image digest,
commit, build log reference, runtime snapshot) to the deployment's CMDB CI,
proving what was deployed matched the change intent.

**Inputs**

| Name | Type | Required | Notes |
|---|---|---|---|
| `trail_id` | String (UUID) | yes | The trail whose deployment provenance to anchor |
| `ci_name` | String | yes | CMDB CI name (service/app) to attach the evidence to |

**Outputs**

| Name | Type | Notes |
|---|---|---|
| `ci_sys_id` | String | the CMDB CI the evidence was anchored to |
| `anchored` | Boolean | true when the CI was updated |
| `audit_package_url` | String | link to the Fides audit package for the trail |

**REST steps**

1. **Locate the CI** — `GET {{base}}/api/v1/servicenow/cmdb?name={{inputs.ci_name}}`
   ([`handleServiceNowSearchCMDB`](https://github.com/olafkfreund/fides/blob/main/pkg/api/server.go)) returns matching
   configuration items; take the `sys_id`.
2. **Fetch the evidence** — `GET {{base}}/api/v1/trails/{{inputs.trail_id}}/audit-package`
   ([`audit.go`](https://github.com/olafkfreund/fides/blob/main/pkg/api/audit.go)) streams the tamper-evident ZIP
   (metadata, artifacts, attestations, chain verdict).
3. **Anchor it** — attach the audit package / write the signed attestation summary
   onto the CI. Today the CMDB write path is the event-driven `CMDBSink`
   (`snapshot.reported` → IRE); PR #228 adds the on-close anchor endpoint this
   action calls directly. Until then, wire step 3 to your CMDB update (attach the
   ZIP to the CI record and stamp the attestation `sys_id`).

This closes the change↔control↔deployment loop: the same Fides attestation
`sys_id` is referenced by the `change_request` (Action 1), the GRC control
(#227), and the CMDB CI (this action), so an auditor traces change → control →
deployment in one hop.

---

## Packaging as a spoke

1. Create a **scoped app** `Fides Spoke` (or import the update-set skeleton).
2. Add the **Connection & Credential alias** `x_fides.api`.
3. Create the three **Actions** above (Action Designer): declare the inputs/outputs
   as listed, add the REST step(s) against the alias, and a script step for the
   pass/fail logic in Actions 2–3.
4. Publish; the actions appear under the **Fides** category in Flow Designer.
5. (Optional) ship example flows: "Gate CR on Fides" (Action 2 on the CR approval),
   "Write Fides risk to CR" (Action 1 on CR create), "Anchor on close" (Action 3
   on CR closed-complete).

See [`hmac-webhook-verification.md`](hmac-webhook-verification.md) for the reverse
direction (Fides → ServiceNow signed events) and
[`now-assist-grounding.md`](now-assist-grounding.md) for surfacing this evidence
to Now Assist.
