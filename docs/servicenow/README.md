# Fides ServiceNow DevGovOps spoke

ServiceNow-side packaging artifacts and integration docs for the Fides ⇄
ServiceNow spoke — epic [#216](https://github.com/olafkfreund/fides/issues/216)
("Fides advises; ServiceNow decides"). These are ServiceNow platform artifacts
(scripts, update-set, action specs) and docs; the Fides-side Go endpoints they
call already exist in [`pkg/api/server.go`](https://github.com/olafkfreund/fides/blob/main/pkg/api/server.go).

For the Fides-side configuration (service account, credential storage, ITOM/CMDB
sinks, the ITSM change-check gate) start at
[`../servicenow-integration.md`](../servicenow-integration.md).

## Contents

| Doc | Issue | What it delivers |
|---|---|---|
| [`hmac-webhook-verification.md`](hmac-webhook-verification.md) | [#229](https://github.com/olafkfreund/fides/issues/229) | Scripted REST API + `FidesWebhookVerifier` Script Include that verify the Fides `X-Fides-Signature` HMAC on inbound webhooks; secret storage + Flow Designer usage note |
| [`flow-designer-actions.md`](flow-designer-actions.md) | [#232](https://github.com/olafkfreund/fides/issues/232) | IntegrationHub spoke spec — three Flow Designer actions ("Attach Fides evidence to change", "Require Fides gate", "Anchor deployment in CMDB") with inputs/outputs + the exact Fides REST steps |
| [`now-assist-grounding.md`](now-assist-grounding.md) | [#233](https://github.com/olafkfreund/fides/issues/233) | Expose Fides control-coverage/evidence as grounding context so Now Assist change-risk predictions are explainable and cryptographically backed |

### Code artifacts

- [`scripted-rest/FidesWebhookVerifier.js`](scripted-rest/FidesWebhookVerifier.js) — reusable HMAC-SHA256 verifier (Script Include).
- [`scripted-rest/fides_inbound_resource.js`](scripted-rest/fides_inbound_resource.js) — Scripted REST resource that verifies + accepts Fides deliveries.
- [`update-set/fides_spoke_update_set.xml`](update-set/fides_spoke_update_set.xml) — importable update-set skeleton (Script Include, Scripted REST API, secret property, connection alias).

## Direction of travel

- **Fides → ServiceNow (signed events):** `hmac-webhook-verification.md`. Fides
  signs every outbound webhook; ServiceNow verifies before trusting the payload.
- **ServiceNow → Fides (spoke actions):** `flow-designer-actions.md`. SN flows call
  Fides to attach evidence/risk, gate changes, and anchor deployments.
- **AI grounding:** `now-assist-grounding.md`. Fides evidence feeds Now Assist.

## Related epics/PRs

The signed-bundle enrichments referenced by the action specs land via sibling PRs
#226 (evidence bundle + risk → change_request), #227 (change↔control linkage), and
#228 (CMDB deployment provenance).
